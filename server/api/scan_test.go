package api

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ShkodnikAI/NetAtlas/scanner"
	"github.com/ShkodnikAI/NetAtlas/scanner/arp"
	"github.com/ShkodnikAI/NetAtlas/scanner/ping"
	"github.com/ShkodnikAI/NetAtlas/scanner/pipeline"
	"github.com/ShkodnikAI/NetAtlas/scanner/snmp"
)

// fakeScanConn — UDP-заглушка без сети: тишина по дедлайну.
type fakeScanConn struct{}

func (c *fakeScanConn) ReadFrom(p []byte) (int, net.Addr, error) {
	return 0, nil, os.ErrDeadlineExceeded
}
func (c *fakeScanConn) WriteTo(b []byte, addr net.Addr) (int, error) { return len(b), nil }
func (c *fakeScanConn) Close() error                                 { return nil }
func (c *fakeScanConn) LocalAddr() net.Addr                          { return nil }
func (c *fakeScanConn) SetDeadline(t time.Time) error                { return nil }
func (c *fakeScanConn) SetReadDeadline(t time.Time) error            { return nil }
func (c *fakeScanConn) SetWriteDeadline(t time.Time) error           { return nil }

// fakeScanWalker — SNMP-заглушка: собирает цели.
type fakeScanWalker struct {
	targetAddr netip.Addr
	seen       *[]netip.Addr
	mu         *sync.Mutex
}

func (w *fakeScanWalker) Get(ctx context.Context, oids ...string) ([]snmp.PDU, error) {
	return nil, nil
}
func (w *fakeScanWalker) Walk(ctx context.Context, root string, fn func(snmp.PDU) error) error {
	w.mu.Lock()
	*w.seen = append(*w.seen, w.targetAddr)
	w.mu.Unlock()
	return nil
}
func (w *fakeScanWalker) Close() error { return nil }

// fakeScanDeps — подставные источники сканирования сервера.
type fakeScanDeps struct {
	mu      sync.Mutex
	readARP int
	seen    []netip.Addr
	block   chan struct{} // не nil — первый запуск держится для проверки 409
}

func (f *fakeScanDeps) deps() ScanDeps {
	return ScanDeps{
		ReadARP: func(ctx context.Context) ([]arp.Entry, error) {
			f.mu.Lock()
			f.readARP++
			f.mu.Unlock()
			if f.block != nil {
				<-f.block
			}
			return []arp.Entry{{IP: netip.MustParseAddr("10.0.0.2"), MAC: "00:00:00:00:00:02"}}, nil
		},
		NewNameConn: func() (net.PacketConn, error) { return &fakeScanConn{}, nil },
		NewProber: func() (ping.Prober, func(), error) {
			return &fakeProber{alive: map[string]bool{"10.0.0.2": true}}, func() {}, nil
		},
		NewWalker: func(target netip.Addr, _ snmp.Auth) (snmp.Walker, error) {
			return &fakeScanWalker{targetAddr: target, seen: &f.seen, mu: &f.mu}, nil
		},
	}
}

var _ = pipeline.Config{}

// scanAPI — API со сканом на подставных зависимостях.
func scanAPI(t *testing.T, st Store, deps *fakeScanDeps, snmpReady bool) http.Handler {
	t.Helper()
	scope, err := scanner.NewScope([]string{"10.0.0.0/24"}, false)
	if err != nil {
		t.Fatalf("scope: %v", err)
	}
	a, err := New(st, token, scope, mustLimiter(t), &fakeProber{})
	if err != nil {
		t.Fatalf("api: %v", err)
	}
	a.ConfigureScan(ServerScanConfig{
		Subnets:   []string{"10.0.0.0/24"},
		SNMPReady: snmpReady,
		SNMPAuth:  snmp.Auth{V2C: true, Community: "public"},
	}, deps.deps())
	return a.Handler()
}

func mustLimiter(t *testing.T) *scanner.Limiter {
	t.Helper()
	l, err := scanner.NewLimiter(4, 1000, nil)
	if err != nil {
		t.Fatalf("limiter: %v", err)
	}
	return l
}

const scanBody = `{"subnets":["10.0.0.0/24"],"ping":true,"confirm":true}`

func scanID(t *testing.T, body string) int64 {
	t.Helper()
	var out struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("ответ без id: %s", body)
	}
	return out.ID
}

// Без подтверждения сканирование не стартует.
func TestScanRequiresConfirm(t *testing.T) {
	fs := newFakeStore()
	h := scanAPI(t, fs, &fakeScanDeps{}, true)
	rec := do(h, "POST", "/api/scan", `{"subnets":["10.0.0.0/24"],"ping":true,"confirm":false}`, bearer)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("код %d, хочу 400: %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), `"id"`) {
		t.Fatalf("сканирование стартовало без confirm: %s", rec.Body.String())
	}
}

// Подсеть вне конфигурации сервера — 400, сканирование не стартует.
func TestScanSubnetOutsideConfig(t *testing.T) {
	fs := newFakeStore()
	h := scanAPI(t, fs, &fakeScanDeps{}, true)
	rec := do(h, "POST", "/api/scan",
		`{"subnets":["192.168.5.0/24"],"ping":false,"confirm":true}`, bearer)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("код %d, хочу 400: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "вне подсетей сервера") {
		t.Fatalf("текст: %s", rec.Body.String())
	}
}

// SNMP-цели без учётных данных сервера — 400 (только имена переменных).
func TestScanSNMPWithoutCreds(t *testing.T) {
	fs := newFakeStore()
	h := scanAPI(t, fs, &fakeScanDeps{}, false)
	rec := do(h, "POST", "/api/scan",
		`{"subnets":["10.0.0.0/24"],"snmp_targets":["10.0.0.2"],"confirm":true}`, bearer)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("код %d, хочу 400: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "NETATLAS_SNMP_") {
		t.Fatalf("текст без имени переменных: %s", rec.Body.String())
	}
}

// Второй одновременный запуск — 409; состояние читается и завершается.
func TestScanSecondRun409AndState(t *testing.T) {
	fs := newFakeStore()
	fs.addDev("00:00:00:00:00:02", netip.MustParseAddr("10.0.0.2"))
	deps := &fakeScanDeps{block: make(chan struct{})}
	h := scanAPI(t, fs, deps, true)

	rec := do(h, "POST", "/api/scan", scanBody, bearer)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("первый запуск: код %d: %s", rec.Code, rec.Body.String())
	}
	id := scanID(t, rec.Body.String())

	if rec := do(h, "POST", "/api/scan", scanBody, bearer); rec.Code != http.StatusConflict {
		t.Fatalf("второй запуск: код %d, хочу 409: %s", rec.Code, rec.Body.String())
	}

	// Состояние: running.
	rec = do(h, "GET", "/api/scan/"+itoa(id), "", bearer)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"running"`) {
		t.Fatalf("состояние: %d %s", rec.Code, rec.Body.String())
	}

	// Завершаем первый запуск и ждём done.
	close(deps.block)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		rec = do(h, "GET", "/api/scan/"+itoa(id), "", bearer)
		if strings.Contains(rec.Body.String(), `"done"`) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !strings.Contains(rec.Body.String(), `"done"`) {
		t.Fatalf("скан не завершился: %s", rec.Body.String())
	}
	// Счётчики и стадии в состоянии.
	if !strings.Contains(rec.Body.String(), `"stages"`) {
		t.Fatalf("нет стадий: %s", rec.Body.String())
	}
	// После завершения новый запуск принимается.
	if rec := do(h, "POST", "/api/scan", scanBody, bearer); rec.Code != http.StatusAccepted {
		t.Fatalf("запуск после завершения: код %d: %s", rec.Code, rec.Body.String())
	}
	// Чужой id — 404.
	if rec := do(h, "GET", "/api/scan/999", "", bearer); rec.Code != http.StatusNotFound {
		t.Fatalf("чужой id: код %d, хочу 404", rec.Code)
	}
}

func itoa(n int64) string {
	return strings.TrimSpace(strings.Replace(jsonNumber(n), "\n", "", -1))
}

func jsonNumber(n int64) string {
	b, _ := json.Marshal(n)
	return string(b)
}

// devices?class= фильтрует по классу; alerts и ack маршруты живые.
func TestDevicesClassAndAlerts(t *testing.T) {
	fs := newFakeStore()
	fs.addDev("00:00:00:00:00:02", netip.MustParseAddr("10.0.0.2"))
	fs.setClass("00:00:00:00:00:02", "guest")
	h := scanAPI(t, fs, &fakeScanDeps{}, true)

	rec := do(h, "GET", "/api/devices?class=guest", "", bearer)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "00:00:00:00:00:02") {
		t.Fatalf("guest: %d %s", rec.Code, rec.Body.String())
	}
	rec = do(h, "GET", "/api/devices?class=managed", "", bearer)
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), "00:00:00:00:00:02") {
		t.Fatalf("managed не должен включать гостя: %s", rec.Body.String())
	}
	rec = do(h, "GET", "/api/devices?class=самозванец", "", bearer)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("плохой класс: код %d, хочу 400", rec.Code)
	}
	rec = do(h, "GET", "/api/devices", "", bearer)
	if rec.Code != http.StatusOK {
		t.Fatalf("без класса: %d", rec.Code)
	}
	rec = do(h, "GET", "/api/alerts", "", bearer)
	if rec.Code != http.StatusOK {
		t.Fatalf("alerts: %d", rec.Code)
	}
	rec = do(h, "POST", "/api/alerts/1/ack", "", bearer)
	if rec.Code != http.StatusOK {
		t.Fatalf("ack: %d: %s", rec.Code, rec.Body.String())
	}
	rec = do(h, "POST", "/api/alerts/7/ack", "", bearer)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("чужой ack: %d, хочу 404", rec.Code)
	}
}

// Конфигурация для мастера: подсети сервера и готовность SNMP без
// самих учётных данных.
func TestConfigRoute(t *testing.T) {
	fs := newFakeStore()
	h := scanAPI(t, fs, &fakeScanDeps{}, true)
	rec := do(h, "GET", "/api/config", "", bearer)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "10.0.0.0/24") {
		t.Fatalf("config: %d %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "public") {
		t.Fatalf("учётные данные утекли в конфигурацию: %s", rec.Body.String())
	}
}
