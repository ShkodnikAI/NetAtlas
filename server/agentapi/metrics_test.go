// Тесты маршрутов метрик и blob (NR-008).
package agentapi

import (
	"net/http"
	"strings"
	"testing"
)

// Метрики принимаются: точки уходят в хранилище.
func TestMetricsAccept(t *testing.T) {
	e := newEnv(t, DefaultRevocationTTL)
	certPEM, _, priv := e.enrollAgent(testCN, "pc-1", nil)
	cl := certClient(pemDER(t, certPEM), priv)
	body := `{"kind":"metrics","schema_ver":1,"collected_at":"2026-10-24T12:00:00Z","samples":[` +
		`{"target":"192.168.1.1","metric":"latency","value":12.5},` +
		`{"target":"192.168.1.1","metric":"loss","value":0.02}]}`
	if code, resp := e.post(cl, e.mtlsURL("/agent/v1/metrics"), []byte(body)); code != http.StatusAccepted {
		t.Fatalf("метрики: код %d: %s", code, resp)
	}
	var n int
	if err := e.st.DB().QueryRow(`SELECT COUNT(*) FROM metrics_raw WHERE agent_id = ?`, testCN).Scan(&n); err != nil || n != 2 {
		t.Fatalf("точек %d (err %v), хочу 2", n, err)
	}
}

// Метрики: лимит тела 256 КБ, строгий JSON, лимит числа точек.
func TestMetricsLimits(t *testing.T) {
	e := newEnv(t, DefaultRevocationTTL)
	certPEM, _, priv := e.enrollAgent(testCN, "pc-1", nil)
	cl := certClient(pemDER(t, certPEM), priv)

	big := strings.Repeat("x", MaxMetricsBody+1024)
	raw := `{"kind":"metrics","schema_ver":1,"samples":[{"target":"` + big + `","metric":"latency","value":1}]}`
	if code, _ := e.post(cl, e.mtlsURL("/agent/v1/metrics"), []byte(raw)); code != http.StatusRequestEntityTooLarge {
		t.Fatalf("большое тело: код %d, хочу 413", code)
	}
	if code, _ := e.post(cl, e.mtlsURL("/agent/v1/metrics"), []byte(`{"kind":"metrics","schema_ver":1,"agent_id":"agent:evil","samples":[]}`)); code != http.StatusBadRequest {
		t.Fatal("подмена agent_id в метриках принята")
	}
	// 513 точек — 400.
	var sb strings.Builder
	sb.WriteString(`{"kind":"metrics","schema_ver":1,"samples":[`)
	for i := 0; i < 513; i++ {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(`{"target":"g","metric":"latency","value":1}`)
	}
	sb.WriteString("]}")
	if code, _ := e.post(cl, e.mtlsURL("/agent/v1/metrics"), []byte(sb.String())); code != http.StatusBadRequest {
		t.Fatalf("513 точек: код %d, хочу 400", code)
	}
}

// Blob: отдаёт ровно N байт, больше 8 МБ — 400; приём до 8 МБ.
func TestBlobLimits(t *testing.T) {
	e := newEnv(t, DefaultRevocationTTL)
	certPEM, _, priv := e.enrollAgent(testCN, "pc-1", nil)
	cl := certClient(pemDER(t, certPEM), priv)

	// GET: 1000 байт.
	resp, err := cl.Get(e.mtlsURL("/agent/v1/blob?bytes=1000"))
	if err != nil {
		t.Fatalf("blob get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("blob get: код %d", resp.StatusCode)
	}
	buf := make([]byte, 4096)
	total := 0
	for {
		n, err := resp.Body.Read(buf)
		total += n
		if err != nil {
			break
		}
	}
	if total != 1000 {
		t.Fatalf("байт %d, хочу 1000", total)
	}
	// GET: больше 8 МБ — 400.
	if resp, err := cl.Get(e.mtlsURL("/agent/v1/blob?bytes=9000000")); err != nil {
		t.Fatalf("blob get 9МБ: %v", err)
	} else if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("bytes>8МБ: код %d, хочу 400", resp.StatusCode)
	} else {
		resp.Body.Close()
	}
	// POST: 1 МБ принимается.
	if code, _ := e.post(cl, e.mtlsURL("/agent/v1/blob"), make([]byte, 1<<20)); code != http.StatusAccepted {
		t.Fatal("1 МБ не принят")
	}
	// POST: 9 МБ — 413.
	if code, _ := e.post(cl, e.mtlsURL("/agent/v1/blob"), make([]byte, 9<<20)); code != http.StatusRequestEntityTooLarge {
		t.Fatalf("9 МБ: код %d, хочу 413", code)
	}
}
