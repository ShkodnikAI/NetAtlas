// Тесты NR-023 в API: проверка цепочки аудита по HTTP, audit_ok в
// /api/config, валидация аренд в POST /api/scan.

package api

import (
	"encoding/json"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ShkodnikAI/NetAtlas/scanner"
	"github.com/ShkodnikAI/NetAtlas/scanner/ping"
	"github.com/ShkodnikAI/NetAtlas/scanner/snmp"
	"github.com/ShkodnikAI/NetAtlas/server/store"
)

// Целая цепочка даёт ok=true; подмена записи (триггеры сняты в тесте)
// даёт ok=false с описанием.
func TestAuditVerifyEndpoint(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "netatlas.db"))
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	a, err := New(st, token, nil, nil, nil)
	if err != nil {
		t.Fatalf("api: %v", err)
	}
	h := a.Handler()

	if _, err := st.AddManualDevice(t.Context(), "device", "элемент", "owner"); err != nil {
		t.Fatalf("ручной элемент: %v", err)
	}
	rec := do(h, "GET", "/api/audit/verify", "", bearer)
	if rec.Code != http.StatusOK {
		t.Fatalf("код %d, хочу 200: %s", rec.Code, rec.Body.String())
	}
	var ok struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &ok); err != nil {
		t.Fatalf("ответ не JSON: %s", rec.Body.String())
	}
	if !ok.OK || ok.Error != "" {
		t.Fatalf("целая цепочка: ok=%v error=%q", ok.OK, ok.Error)
	}

	// Атака: правка записи поверх снятых триггеров.
	for _, trig := range []string{"audit_log_no_update", "audit_log_no_delete"} {
		if _, err := st.DB().Exec("DROP TRIGGER " + trig); err != nil {
			t.Fatalf("снятие %s: %v", trig, err)
		}
	}
	if _, err := st.DB().Exec(`UPDATE audit_log SET actor = 'злоумышленник' WHERE id = 1`); err != nil {
		t.Fatalf("подмена: %v", err)
	}
	rec = do(h, "GET", "/api/audit/verify", "", bearer)
	if rec.Code != http.StatusOK {
		t.Fatalf("код %d, хочу 200: %s", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &ok); err != nil {
		t.Fatalf("ответ не JSON: %s", rec.Body.String())
	}
	if ok.OK || ok.Error == "" {
		t.Fatalf("подменённая цепочка: ok=%v error=%q", ok.OK, ok.Error)
	}
}

// /api/config отдаёт audit_ok: по умолчанию true, после
// SetAuditOK(false) — false (разрыв на старте сервера).
func TestConfigAuditOK(t *testing.T) {
	fs := newFakeStore()
	a, err := New(fs, token, nil, nil, nil)
	if err != nil {
		t.Fatalf("api: %v", err)
	}
	h := a.Handler()

	rec := do(h, "GET", "/api/config", "", bearer)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"audit_ok":true`) {
		t.Fatalf("по умолчанию: %d %s", rec.Code, rec.Body.String())
	}
	a.SetAuditOK(false)
	rec = do(h, "GET", "/api/config", "", bearer)
	if !strings.Contains(rec.Body.String(), `"audit_ok":false`) {
		t.Fatalf("после разрыва: %s", rec.Body.String())
	}
}

// Валидация аренд: поля только вместе, путь абсолютный без «..»,
// формат isc|csv, файл доступен и не больше лимита. Ошибка — 400 и
// сканирование не стартует.
func TestScanLeasesValidation(t *testing.T) {
	big := filepath.Join(t.TempDir(), "big.csv")
	if err := os.WriteFile(big, make([]byte, 5<<20+1), 0o600); err != nil {
		t.Fatalf("большой файл: %v", err)
	}
	absent := filepath.Join(t.TempDir(), "absent.csv")
	cases := []struct {
		name string
		body string
		want string
	}{
		{"только путь", `{"subnets":["10.0.0.0/24"],"confirm":true,"leases_path":"/tmp/x.csv"}`, "вместе"},
		{"только формат", `{"subnets":["10.0.0.0/24"],"confirm":true,"leases_format":"csv"}`, "вместе"},
		{"чужой формат", `{"subnets":["10.0.0.0/24"],"confirm":true,"leases_path":"/tmp/x.csv","leases_format":"json"}`, "допустимы"},
		{"относительный путь", `{"subnets":["10.0.0.0/24"],"confirm":true,"leases_path":"leases.csv","leases_format":"csv"}`, "абсолютным"},
		{"путь с ..", `{"subnets":["10.0.0.0/24"],"confirm":true,"leases_path":"/tmp/../etc/passwd","leases_format":"csv"}`, "запрещён"},
		{"файл недоступен", `{"subnets":["10.0.0.0/24"],"confirm":true,"leases_path":"` + absent + `","leases_format":"csv"}`, "недоступен"},
		{"больше лимита", `{"subnets":["10.0.0.0/24"],"confirm":true,"leases_path":"` + big + `","leases_format":"csv"}`, "больше"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fs := newFakeStore()
			h := scanAPI(t, fs, &fakeScanDeps{}, true)
			rec := do(h, "POST", "/api/scan", tc.body, bearer)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("код %d, хочу 400: %s", rec.Code, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), tc.want) {
				t.Fatalf("текст %q не найден: %s", tc.want, rec.Body.String())
			}
			// Сканирование не стартовало: идентификатора в ответе нет.
			if strings.Contains(rec.Body.String(), `"id":`) {
				t.Fatalf("сканирование стартовало при ошибке валидации: %s", rec.Body.String())
			}
		})
	}
}

// Корректный файл аренд: скан завершается, арендное устройство
// сохраняется с наблюдением dhcp и именем из аренды.
func TestScanWithLeases(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "netatlas.db"))
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	leases := filepath.Join(t.TempDir(), "dhcpd.leases")
	content := "mac,ip,hostname,ssid,expires\n" +
		"AA:BB:CC:00:00:23,10.0.0.44,lab-laptop,Office,\n"
	if err := os.WriteFile(leases, []byte(content), 0o600); err != nil {
		t.Fatalf("файл аренд: %v", err)
	}
	deps := &fakeScanDeps{}
	h := scanAPI(t, st, deps, true)
	body := `{"subnets":["10.0.0.0/24"],"ping":true,"confirm":true,"leases_path":"` + leases + `","leases_format":"csv"}`
	rec := do(h, "POST", "/api/scan", body, bearer)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("код %d, хочу 202: %s", rec.Code, rec.Body.String())
	}
	id := scanID(t, rec.Body.String())
	deadline := time.Now().Add(10 * time.Second)
	state := ""
	for time.Now().Before(deadline) {
		state = do(h, "GET", "/api/scan/"+itoa(id), "", bearer).Body.String()
		if strings.Contains(state, `"done"`) || strings.Contains(state, `"failed"`) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !strings.Contains(state, `"done"`) {
		t.Fatalf("скан не завершился успешно: %s", state)
	}
	if !strings.Contains(state, `"leases":1`) {
		t.Fatalf("счётчик аренд: %s", state)
	}
	ctx := t.Context()
	info, err := st.Device(ctx, "aa:bb:cc:00:00:23") // MAC нормализуется парсером
	if err != nil {
		t.Fatalf("арендное устройство не сохранено: %v", err)
	}
	foundIP := false
	for _, ip := range info.IPs {
		if ip == netip.MustParseAddr("10.0.0.44") {
			foundIP = true
		}
	}
	if !foundIP {
		t.Fatalf("адрес аренды не сохранён: %v", info.IPs)
	}
	foundObs := false
	for _, o := range info.Observations {
		if o.Source == "dhcp" {
			foundObs = true
		}
	}
	if !foundObs {
		t.Fatalf("наблюдения: %+v, хочу dhcp", info.Observations)
	}
}

// Хосты без MAC доходят до хранилища при серверном сканировании:
// живой адрес без записи ARP сохраняется как ip:устройство (NR-023).
func TestScanSavesHostsWithoutMAC(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "netatlas.db"))
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	scope, err := scanner.NewScope([]string{"10.0.0.0/24"}, false)
	if err != nil {
		t.Fatalf("scope: %v", err)
	}
	deps := fakeScanDeps{}
	d := deps.deps()
	d.NewProber = func() (ping.Prober, func(), error) {
		return &fakeProber{alive: map[string]bool{"10.0.0.77": true}}, func() {}, nil
	}
	a, err := New(st, token, scope, mustLimiter(t), &fakeProber{})
	if err != nil {
		t.Fatalf("api: %v", err)
	}
	a.ConfigureScan(ServerScanConfig{
		Subnets:   []string{"10.0.0.0/24"},
		SNMPReady: true,
		SNMPAuth:  snmp.Auth{V2C: true, Community: "public"},
	}, d)
	h := a.Handler()

	body := `{"subnets":["10.0.0.0/24"],"ping":true,"names":false,"confirm":true}`
	rec := do(h, "POST", "/api/scan", body, bearer)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("код %d, хочу 202: %s", rec.Code, rec.Body.String())
	}
	id := scanID(t, rec.Body.String())
	deadline := time.Now().Add(10 * time.Second)
	state := ""
	for time.Now().Before(deadline) {
		state = do(h, "GET", "/api/scan/"+itoa(id), "", bearer).Body.String()
		if strings.Contains(state, `"done"`) || strings.Contains(state, `"failed"`) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !strings.Contains(state, `"done"`) {
		t.Fatalf("скан не завершился успешно: %s", state)
	}
	if !strings.Contains(state, `"hosts":1`) {
		t.Fatalf("счётчик хостов: %s", state)
	}
	info, err := st.Device(t.Context(), "ip:10.0.0.77")
	if err != nil {
		t.Fatalf("ip-хост не сохранён: %v", err)
	}
	var kind string
	if err := st.DB().QueryRow(
		`SELECT kind FROM devices WHERE id = 'ip:10.0.0.77'`).Scan(&kind); err != nil {
		t.Fatalf("kind: %v", err)
	}
	if kind != "host" {
		t.Fatalf("kind %q, хочу host", kind)
	}
	found := false
	for _, o := range info.Observations {
		if o.Source == "ping" {
			found = true
		}
	}
	if !found {
		t.Fatalf("наблюдения %+v, хочу ping", info.Observations)
	}
}
