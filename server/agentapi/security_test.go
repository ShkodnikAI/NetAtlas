// Тесты маршрута проверок безопасности (NR-010): приём, границы,
// отказы. Всё через ту же обвязку mTLS, что и остальные маршруты.
package agentapi

import (
	"net/http"
	"strings"
	"testing"
)

// happy — корректный отчёт проверок.
const happySecurity = `{"kind":"security","schema_ver":1,"collected_at":"2026-10-24T12:00:00Z","results":[` +
	`{"id":"smbv1","status":"fail","detail":"SMBv1 включён"},` +
	`{"id":"bitlocker","status":"unknown","detail":"командлета нет"},` +
	`{"id":"firewall","status":"pass"},` +
	`{"id":"ports","status":"pass","detail":"слушающих портов: 1","data":{"ports":[{"local_address":"0.0.0.0","local_port":445}]}}]}`

func TestSecurityAccept(t *testing.T) {
	e := newEnv(t, DefaultRevocationTTL)
	certPEM, _, priv := e.enrollAgent(testCN, "pc-1", nil)
	cl := certClient(pemDER(t, certPEM), priv)
	if code, resp := e.post(cl, e.mtlsURL("/agent/v1/security"), []byte(happySecurity)); code != http.StatusAccepted {
		t.Fatalf("отчёт: код %d: %s", code, resp)
	}
	var n int
	if err := e.st.DB().QueryRow(`SELECT COUNT(*) FROM agent_security WHERE agent_id = ?`, testCN).Scan(&n); err != nil || n != 1 {
		t.Fatalf("отчётов %d (err %v), хочу 1", n, err)
	}
	// Аудит: приём отчёта записан (action agent_security).
	var actions int
	if err := e.st.DB().QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action = 'agent_security'`).Scan(&actions); err != nil || actions != 1 {
		t.Fatalf("записей аудита %d (err %v), хочу 1", actions, err)
	}
	// Повторный отчёт сохраняется (история append-only).
	if code, _ := e.post(cl, e.mtlsURL("/agent/v1/security"), []byte(happySecurity)); code != http.StatusAccepted {
		t.Fatal("повторный отчёт не принят")
	}
	if err := e.st.DB().QueryRow(`SELECT COUNT(*) FROM agent_security WHERE agent_id = ?`, testCN).Scan(&n); err != nil || n != 2 {
		t.Fatalf("отчётов после повтора %d, хочу 2", n)
	}
}

func TestSecurityDenies(t *testing.T) {
	e := newEnv(t, DefaultRevocationTTL)
	certPEM, _, priv := e.enrollAgent(testCN, "pc-1", nil)
	cl := certClient(pemDER(t, certPEM), priv)

	cases := []struct {
		name string
		body string
		code int
	}{
		{"чужой kind", `{"kind":"inventory","schema_ver":1,"results":[]}`, http.StatusBadRequest},
		{"schema 0", `{"kind":"security","schema_ver":0,"results":[]}`, http.StatusBadRequest},
		{"подмена agent_id", `{"kind":"security","schema_ver":1,"agent_id":"agent:evil","results":[]}`, http.StatusBadRequest},
		{"недопустимый статус", `{"kind":"security","schema_ver":1,"results":[{"id":"smbv1","status":"safe"}]}`, http.StatusBadRequest},
		{"пустой id", `{"kind":"security","schema_ver":1,"results":[{"id":"","status":"pass"}]}`, http.StatusBadRequest},
		{"повтор id", `{"kind":"security","schema_ver":1,"results":[{"id":"smbv1","status":"pass"},{"id":"smbv1","status":"pass"}]}`, http.StatusBadRequest},
		{"неизвестное поле", `{"kind":"security","schema_ver":1,"results":[],"extra":1}`, http.StatusBadRequest},
		{"data не JSON", `{"kind":"security","schema_ver":1,"results":[{"id":"ports","status":"pass","data":"раз-два"}]}`, http.StatusBadRequest},
	}
	for _, c := range cases {
		if code, _ := e.post(cl, e.mtlsURL("/agent/v1/security"), []byte(c.body)); code != c.code {
			t.Fatalf("%s: код %d, хочу %d", c.name, code, c.code)
		}
	}
	// 65 проверок — 400.
	var sb strings.Builder
	sb.WriteString(`{"kind":"security","schema_ver":1,"results":[`)
	for i := 0; i < MaxSecurityResults+1; i++ {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(`{"id":"check`)
		sb.WriteString(itoa(i))
		sb.WriteString(`","status":"pass"}`)
	}
	sb.WriteString("]}")
	if code, _ := e.post(cl, e.mtlsURL("/agent/v1/security"), []byte(sb.String())); code != http.StatusBadRequest {
		t.Fatalf("65 проверок: код %d, хочу 400", code)
	}
	// detail длиннее лимита — 400.
	long := strings.Repeat("д", MaxCheckDetailLen+1)
	if code, _ := e.post(cl, e.mtlsURL("/agent/v1/security"),
		[]byte(`{"kind":"security","schema_ver":1,"results":[{"id":"smbv1","status":"fail","detail":"`+long+`"}]}`)); code != http.StatusBadRequest {
		t.Fatalf("длинный detail: код %d, хочу 400", code)
	}
	// Отказы в аудите.
	var denies int
	if err := e.st.DB().QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action = 'agent_security' AND result = 'deny'`).Scan(&denies); err != nil || denies < 8 {
		t.Fatalf("отказов в аудите %d, хочу не меньше 8", denies)
	}
}

// Отчёт от агента без сертификата не доходит (отказ на handshake).
func TestSecurityNoCert(t *testing.T) {
	e := newEnv(t, DefaultRevocationTTL)
	e.requestRejected(plainClient(), e.mtlsURL("/agent/v1/security"))
}

// itoa — без strconv в тестовом файле (число < 1000).
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
