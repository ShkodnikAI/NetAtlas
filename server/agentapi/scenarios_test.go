package agentapi

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ShkodnikAI/NetAtlas/pki"
	"github.com/ShkodnikAI/NetAtlas/server/store"
)

// pemDER — DER из PEM-строки сертификата.
func pemDER(t *testing.T, certPEM string) []byte {
	t.Helper()
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		t.Fatalf("сертификат не PEM")
	}
	return block.Bytes
}

// enrollClient — регистрирует агента и возвращает готовый TLS-клиент.
func (e *env) enrollClient(cn, hostname string, macs []string) (*http.Client, string) {
	e.t.Helper()
	certPEM, serial, priv := e.enrollAgent(cn, hostname, macs)
	return certClient(pemDER(e.t, certPEM), priv), serial
}

// Полный путь: регистрация → карточка → checkin → инвентарь.
func TestEnrollCheckinInventoryFlow(t *testing.T) {
	e := newEnv(t, DefaultRevocationTTL)
	certPEM, serial, priv := e.enrollAgent(testCN, "pc-1", []string{"AA-BB-CC-DD-EE-01", "aabb.ccdd.ee02"})

	// MAC-список нормализован, устройства получили managed.
	agent, err := e.st.AgentByID(context.Background(), testCN)
	if err != nil {
		t.Fatalf("AgentByID: %v", err)
	}
	if agent.Status != "active" || agent.CertSerial != serial {
		t.Fatalf("карточка агента: %+v (serial %q)", agent, serial)
	}
	if len(agent.MACList) != 2 ||
		agent.MACList[0] != "aa:bb:cc:dd:ee:01" || agent.MACList[1] != "aa:bb:cc:dd:ee:02" {
		t.Fatalf("mac_list = %v", agent.MACList)
	}
	for _, mac := range agent.MACList {
		dev, err := e.st.Device(context.Background(), mac)
		if err != nil {
			t.Fatalf("устройство %s: %v", mac, err)
		}
		if dev.Class != "managed" {
			t.Fatalf("класс устройства %s = %q, хочу managed", mac, dev.Class)
		}
	}
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatal("выданный сертификат не PEM CERTIFICATE")
	}
	cl := certClient(block.Bytes, priv)

	// checkin: пустой список заданий и интервал опроса.
	code, body := e.post(cl, e.mtlsURL("/agent/v1/checkin"), nil)
	if code != http.StatusOK {
		t.Fatalf("checkin: код %d: %s", code, body)
	}
	var ci checkinResponse
	if err := json.Unmarshal(body, &ci); err != nil {
		t.Fatalf("ответ checkin не разбирается: %v", err)
	}
	if len(ci.Jobs) != 0 {
		t.Fatalf("заданий при checkin быть не должно: %v", ci.Jobs)
	}
	if ci.PollSec != 2 {
		t.Fatalf("poll_interval_s = %d, хочу 2 (интервал из New)", ci.PollSec)
	}
	agent, err = e.st.AgentByID(context.Background(), testCN)
	if err != nil {
		t.Fatalf("AgentByID после checkin: %v", err)
	}
	if agent.LastSeen.IsZero() {
		t.Fatal("last_seen не обновлён")
	}

	// Инвентарь принимается и сохраняется как есть.
	inv := []byte(`{"kind":"osinfo","schema_ver":3,"collected_at":"2026-10-24T10:00:00Z","payload":{"os":"linux","arch":"amd64"}}`)
	code, body = e.post(cl, e.mtlsURL("/agent/v1/inventory"), inv)
	if code != http.StatusAccepted {
		t.Fatalf("inventory: код %d: %s", code, body)
	}
	var n int
	if err := e.st.DB().QueryRow(
		`SELECT COUNT(*) FROM agent_inventory WHERE agent_id = ? AND kind = 'osinfo' AND schema_ver = 3`,
		testCN).Scan(&n); err != nil || n != 1 {
		t.Fatalf("порций инвентаря = %d (err %v), хочу 1", n, err)
	}
	if got := auditActions(e); got["agent_inventory/ok"] != 1 {
		t.Fatalf("аудит инвентаря: %v", got)
	}
}

// Токены: чужой, просроченный, использованный — все отвергаются.
func TestEnrollTokenValidation(t *testing.T) {
	e := newEnv(t, DefaultRevocationTTL)
	csrPEM, _ := newCSRPair(t, testCN)

	// Чужой (несуществующий) токен.
	body := enrollBody(t, func(r *enrollRequest) { r.CSRPEM = string(csrPEM); r.Token = "deadbeef" })
	if code, resp := e.post(plainClient(), e.enrollURL(), body); code != http.StatusUnauthorized {
		t.Fatalf("чужой токен: код %d: %s", code, resp)
	}

	// Просроченный: срок сдвигается в прошлое напрямую в базе.
	token := e.issueToken()
	body = enrollBody(t, func(r *enrollRequest) { r.CSRPEM = string(csrPEM); r.Token = token })
	if _, err := e.st.DB().Exec(`UPDATE enroll_tokens SET expires = ?`,
		time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("сдвиг срока: %v", err)
	}
	if code, resp := e.post(plainClient(), e.enrollURL(), body); code != http.StatusUnauthorized {
		t.Fatalf("просроченный токен: код %d: %s", code, resp)
	}

	// Использованный: первая регистрация проходит, вторая — 409.
	token2 := e.issueToken()
	body2 := enrollBody(t, func(r *enrollRequest) { r.CSRPEM = string(csrPEM); r.Token = token2 })
	code, resp := e.post(plainClient(), e.enrollURL(), body2)
	if code != http.StatusCreated {
		t.Fatalf("первая регистрация: код %d: %s", code, resp)
	}
	if code, resp := e.post(plainClient(), e.enrollURL(), body2); code != http.StatusConflict {
		t.Fatalf("повтор токена: код %d, хочу 409: %s", code, resp)
	}
}

// Плохие CSR: мусор, чужой префикс CN, подделанная подпись. Токен
// при этом не расходуется — чистая регистрация с ним проходит.
func TestEnrollRejectsBadCSR(t *testing.T) {
	e := newEnv(t, DefaultRevocationTTL)

	// Мусор вместо CSR.
	body := enrollBody(t, func(r *enrollRequest) { r.CSRPEM = "не PEM" })
	if code, resp := e.post(plainClient(), e.enrollURL(), body); code != http.StatusBadRequest {
		t.Fatalf("мусорный CSR: код %d: %s", code, resp)
	}

	// CN вне схемы agent:.
	csrWrong, _ := newCSRPair(t, "evil-host")
	body = enrollBody(t, func(r *enrollRequest) { r.CSRPEM = string(csrWrong) })
	if code, resp := e.post(plainClient(), e.enrollURL(), body); code != http.StatusBadRequest {
		t.Fatalf("CN без agent:: код %d: %s", code, resp)
	}

	// Подделанная подпись: в DER валидного CSR подменяется байт.
	csrPEM, _ := newCSRPair(t, testCN)
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		t.Fatal("CSR не PEM")
	}
	der := append([]byte(nil), block.Bytes...)
	der[len(der)-3] ^= 0xFF // бит внутри подписи запроса
	tamperedPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
	body = enrollBody(t, func(r *enrollRequest) { r.CSRPEM = string(tamperedPEM) })
	if code, resp := e.post(plainClient(), e.enrollURL(), body); code != http.StatusBadRequest {
		t.Fatalf("подделанный CSR: код %d: %s", code, resp)
	}

	// Токен жив: чистый CSR регистрируется.
	token := e.issueToken()
	body = enrollBody(t, func(r *enrollRequest) { r.CSRPEM = string(csrPEM); r.Token = token })
	if code, resp := e.post(plainClient(), e.enrollURL(), body); code != http.StatusCreated {
		t.Fatalf("токен сгорел от отказов: код %d: %s", code, resp)
	}
}

// Подмена личности в теле: поля agent_id не существует, строгий
// разбор отклоняет его целиком.
func TestEnrollSpoofedAgentID(t *testing.T) {
	e := newEnv(t, DefaultRevocationTTL)
	// CSR валидный: иначе 400 даёт мусорный CSR, а не отказ строгого
	// разбора, и снятие проверки не ловится.
	csrPEM, _ := newCSRPair(t, testCN)
	payload := map[string]any{
		"token": "x", "csr_pem": string(csrPEM), "hostname": "pc",
		"macs": []string{}, "agent_id": "agent:evil",
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if code, resp := e.post(plainClient(), e.enrollURL(), raw); code != http.StatusBadRequest {
		t.Fatalf("подмена agent_id в enroll: код %d, хочу 400: %s", code, resp)
	}
}

// Тело регистрации больше 64 КБ — 413.
func TestEnrollBodyLimit(t *testing.T) {
	e := newEnv(t, DefaultRevocationTTL)
	// Литерал: мутация константы сервера не должна масштабировать тест.
	big := strings.Repeat("A", 64<<10+1024)
	raw := `{"token":"x","csr_pem":"` + big + `","hostname":"pc"}`
	if code, resp := e.post(plainClient(), e.enrollURL(), []byte(raw)); code != http.StatusRequestEntityTooLarge {
		t.Fatalf("большое тело: код %d, хочу 413: %s", code, resp)
	}
}

// Не больше 10 запросов регистрации в минуту с адреса.
func TestEnrollRateLimit(t *testing.T) {
	e := newEnv(t, DefaultRevocationTTL)
	body := enrollBody(t, func(r *enrollRequest) { r.Token = "deadbeef" })
	// Цикл — литералом, а не константой пакета: мутация константы
	// сервера не должна раздувать сам тест.
	for i := 0; i < 10; i++ {
		if code, resp := e.post(plainClient(), e.enrollURL(), body); code != http.StatusUnauthorized {
			t.Fatalf("попытка %d: код %d, хочу 401: %s", i+1, code, resp)
		}
	}
	if code, resp := e.post(plainClient(), e.enrollURL(), body); code != http.StatusTooManyRequests {
		t.Fatalf("попытка 11: код %d, хочу 429: %s", code, resp)
	}
}

// Неизвестный агент: сертификат подписан нашим CA, но регистрации
// не было — handshake проходит, маршрут отвечает 403 с аудитом.
func TestCheckinUnknownAgent403(t *testing.T) {
	e := newEnv(t, time.Hour)
	ghost := "agent:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	der, key := mintCert(t, e.ca, ghost, time.Now().Add(-time.Hour), time.Now().Add(time.Hour), x509.ExtKeyUsageClientAuth)
	cl := certClient(der, key)
	if code, resp := e.post(cl, e.mtlsURL("/agent/v1/checkin"), nil); code != http.StatusForbidden {
		t.Fatalf("неизвестный агент: код %d, хочу 403: %s", code, resp)
	}
	if got := auditActions(e); got["agent_checkin/deny"] < 1 {
		t.Fatalf("нет отказа в журнале: %v", got)
	}
}

// На mTLS-порте маршрута регистрации нет: смешивания обработчиков
// с enroll-слушателем не происходит.
func TestMTLSMuxHasNoEnroll(t *testing.T) {
	e := newEnv(t, DefaultRevocationTTL)
	cl, _ := e.enrollClient(testCN, "pc-1", nil)
	if code, _ := e.post(cl, e.mtlsURL("/agent/v1/enroll"), []byte(`{}`)); code != http.StatusNotFound {
		t.Fatalf("enroll на mTLS-порте: код %d, хочу 404", code)
	}
}

// Личность из тела не работает: checkin не читает тело, инвентарь
// отвергает чужие поля; запись идёт на CN сертификата.
func TestIdentityFromCertNotBody(t *testing.T) {
	e := newEnv(t, DefaultRevocationTTL)
	cl, _ := e.enrollClient(testCN, "pc-1", nil)

	// checkin игнорирует любое тело: подмена не влияет.
	if code, _ := e.post(cl, e.mtlsURL("/agent/v1/checkin"),
		[]byte(`{"agent_id":"agent:evil"}`)); code != http.StatusOK {
		t.Fatal("checkin с подменённым телом не прошёл")
	}
	agent, err := e.st.AgentByID(context.Background(), testCN)
	if err != nil || agent.LastSeen.IsZero() {
		t.Fatalf("last_seen чужого агента не должен был обновиться: %+v (err %v)", agent, err)
	}
	if _, err := e.st.AgentByID(context.Background(), "agent:evil"); err != store.ErrNotFound {
		t.Fatalf("агент agent:evil не должен существовать: %v", err)
	}
	// Инвентарь: поле agent_id отклоняется строгим разбором.
	if code, _ := e.post(cl, e.mtlsURL("/agent/v1/inventory"),
		[]byte(`{"kind":"x","schema_ver":1,"payload":{},"agent_id":"agent:evil"}`)); code != http.StatusBadRequest {
		t.Fatal("подмена agent_id в инвентаре принята")
	}
}

// Отзыв агента: сразу после отзыва (кэш handshake ещё свежий)
// маршруты отвечают 403 по свежей проверке статуса; отказы в аудите.
func TestRevokedAgentFreshCheck403(t *testing.T) {
	e := newEnv(t, time.Hour) // кэш handshake не обновится в течение теста
	cl, _ := e.enrollClient(testCN, "pc-1", nil)
	if code, _ := e.post(cl, e.mtlsURL("/agent/v1/checkin"), nil); code != http.StatusOK {
		t.Fatalf("до отзыва: код %d, хочу 200", code)
	}
	if err := e.st.RevokeAgent(context.Background(), testCN, "owner"); err != nil {
		t.Fatalf("RevokeAgent: %v", err)
	}
	if code, resp := e.post(cl, e.mtlsURL("/agent/v1/checkin"), nil); code != http.StatusForbidden {
		t.Fatalf("после отзыва: код %d, хочу 403: %s", code, resp)
	}
	if code, resp := e.post(cl, e.mtlsURL("/agent/v1/inventory"),
		[]byte(`{"kind":"x","schema_ver":1,"payload":{}}`)); code != http.StatusForbidden {
		t.Fatalf("инвентарь после отзыва: код %d, хочу 403: %s", code, resp)
	}
	if got := auditActions(e); got["agent_checkin/deny"] < 1 {
		t.Fatalf("нет отказа в журнале: %v", got)
	}
}

// Отозванный агент и отозванный серийник отвергаются на handshake
// после обновления кэша (наряд: тест обязан падать, если снять
// проверку отзыва).
func TestRevokedHandshakeRejected(t *testing.T) {
	e := newEnv(t, 30*time.Millisecond)
	cn2 := "agent:99999999-8888-7777-6666-555555555555"
	cl1, _ := e.enrollClient(testCN, "pc-1", nil)
	cl2, serial2 := e.enrollClient(cn2, "pc-2", nil)

	if code, _ := e.post(cl1, e.mtlsURL("/agent/v1/checkin"), nil); code != http.StatusOK {
		t.Fatalf("агент 1 до отзыва: код %d", code)
	}
	if code, _ := e.post(cl2, e.mtlsURL("/agent/v1/checkin"), nil); code != http.StatusOK {
		t.Fatalf("агент 2 до отзыва: код %d", code)
	}

	// Агент 1 — отзыв статуса; агент 2 — отзыв сертификата по серийнику.
	if err := e.st.RevokeAgent(context.Background(), testCN, "owner"); err != nil {
		t.Fatalf("RevokeAgent: %v", err)
	}
	if err := e.st.RevokeCert(context.Background(), serial2, "owner"); err != nil {
		t.Fatalf("RevokeCert: %v", err)
	}
	time.Sleep(100 * time.Millisecond) // кэш списка отзыва протухает

	e.requestRejected(cl1, e.mtlsURL("/agent/v1/checkin"))
	e.requestRejected(cl2, e.mtlsURL("/agent/v1/checkin"))
}

// Без клиентского сертификата mTLS-порты не отвечают (тест обязан
// падать, если снять RequireAndVerifyClientCert).
func TestNoClientCertRejected(t *testing.T) {
	e := newEnv(t, DefaultRevocationTTL)
	e.requestRejected(plainClient(), e.mtlsURL("/agent/v1/checkin"))
	e.requestRejected(plainClient(), e.mtlsURL("/agent/v1/inventory"))
}

// Сертификат чужого CA отвергается: доверенный корень один.
func TestForeignCACertRejected(t *testing.T) {
	e := newEnv(t, DefaultRevocationTTL)
	foreignDir := t.TempDir()
	if err := pki.InitDir(foreignDir); err != nil {
		t.Fatalf("InitDir чужого CA: %v", err)
	}
	foreignCA, err := pki.LoadCA(foreignDir)
	if err != nil {
		t.Fatalf("LoadCA чужого CA: %v", err)
	}
	der, key := mintCert(t, foreignCA, testCN, time.Now().Add(-time.Hour), time.Now().Add(time.Hour), x509.ExtKeyUsageClientAuth)
	e.requestRejected(certClient(der, key), e.mtlsURL("/agent/v1/checkin"))
}

// Просроченный сертификат отвергается.
func TestExpiredCertRejected(t *testing.T) {
	e := newEnv(t, DefaultRevocationTTL)
	der, key := mintCert(t, e.ca, testCN, time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour), x509.ExtKeyUsageClientAuth)
	e.requestRejected(certClient(der, key), e.mtlsURL("/agent/v1/checkin"))
}

// Серверный сертификат не годится как клиентский: EKU строго
// разделены.
func TestServerCertAsClientRejected(t *testing.T) {
	e := newEnv(t, DefaultRevocationTTL)
	certPEM, keyPEM, err := e.ca.IssueServerCert(testCN, time.Now())
	if err != nil {
		t.Fatalf("IssueServerCert: %v", err)
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("пара сервера: %v", err)
	}
	e.requestRejected(certClient(pair.Certificate[0], pair.PrivateKey), e.mtlsURL("/agent/v1/checkin"))
}

// TLS 1.2 не принимается: MinVersion строго 1.3. Клиент — с
// валидным сертификатом: иначе handshake ломается и на версии, и на
// отсутствии сертификата, и снятие MinVersion не ловится.
func TestTLS12Rejected(t *testing.T) {
	e := newEnv(t, DefaultRevocationTTL)
	certPEM, _, priv := e.enrollAgent(testCN, "pc-1", nil)
	e.requestRejected(tls12Client(pemDER(t, certPEM), priv), e.mtlsURL("/agent/v1/checkin"))
}

// Инвентарь: лимит тела 2 МБ и проверка полей конверта.
func TestInventoryLimits(t *testing.T) {
	e := newEnv(t, DefaultRevocationTTL)
	cl, _ := e.enrollClient(testCN, "pc-1", nil)

	big := strings.Repeat("x", 2<<20+1024)
	raw := `{"kind":"osinfo","schema_ver":1,"payload":{"blob":"` + big + `"}}`
	if code, resp := e.post(cl, e.mtlsURL("/agent/v1/inventory"), []byte(raw)); code != http.StatusRequestEntityTooLarge {
		t.Fatalf("большой инвентарь: код %d, хочу 413: %s", code, resp)
	}
	if code, _ := e.post(cl, e.mtlsURL("/agent/v1/inventory"),
		[]byte(`{"kind":"x","schema_ver":0,"payload":{}}`)); code != http.StatusBadRequest {
		t.Fatal("schema_ver=0 принят")
	}
	if code, _ := e.post(cl, e.mtlsURL("/agent/v1/inventory"),
		[]byte(`{"kind":"x","schema_ver":1,"payload":[1,2]}`)); code != http.StatusBadRequest {
		t.Fatal("payload-массив принят")
	}
	if code, _ := e.post(cl, e.mtlsURL("/agent/v1/inventory"),
		[]byte(`{"kind":"x",`)); code != http.StatusBadRequest {
		t.Fatal("ломаный JSON принят")
	}
}
