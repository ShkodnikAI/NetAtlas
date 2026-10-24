// Тесты маршрутов качества (NR-008) на фейковом хранилище.
package api

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/ShkodnikAI/NetAtlas/server/store"
)

// Матрица: с метриками — ячейки с состоянием; без — пусто.
func TestQualityMatrix(t *testing.T) {
	fs := newFakeStore()
	fs.addAgent("agent:one")
	fs.metrics["agent:one"] = []store.MetricAgg{
		{AgentID: "agent:one", Target: "192.168.1.1", Kind: "latency", Avg: 12.5, P95: 20, Max: 30},
		{AgentID: "agent:one", Target: "192.168.1.1", Kind: "loss", Avg: 0.03, P95: 0.05, Max: 0.1},
	}
	a := newRulesAPI(t, fs)
	rec := do(a.Handler(), "GET", "/api/quality/matrix", "", bearer)
	if rec.Code != http.StatusOK {
		t.Fatalf("код %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Matrix []qualityTarget `json:"matrix"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("ответ: %v", err)
	}
	if len(resp.Matrix) != 1 {
		t.Fatalf("ячеек %d, хочу 1", len(resp.Matrix))
	}
	// Потери 3% > 2% → worst = warning.
	if resp.Matrix[0].Worst != "warning" {
		t.Fatalf("состояние %q, хочу warning", resp.Matrix[0].Worst)
	}
	if resp.Matrix[0].Latest["latency"] != 12.5 {
		t.Fatalf("последние значения: %+v", resp.Matrix[0].Latest)
	}
	// Пустая матрица — 200 с пустым списком.
	fs2 := newFakeStore()
	fs2.addAgent("agent:empty")
	a2 := newRulesAPI(t, fs2)
	if rec := do(a2.Handler(), "GET", "/api/quality/matrix", "", bearer); rec.Code != http.StatusOK {
		t.Fatalf("пустая матрица: код %d", rec.Code)
	}
}

// Узкие места: потери 6% → loss_very_high.
func TestQualityBottlenecks(t *testing.T) {
	fs := newFakeStore()
	fs.addAgent("agent:one")
	fs.metrics["agent:one"] = []store.MetricAgg{
		{AgentID: "agent:one", Target: "192.168.1.1", Kind: "loss", Avg: 0.06, P95: 0.06, Max: 0.06},
	}
	a := newRulesAPI(t, fs)
	rec := do(a.Handler(), "GET", "/api/quality/bottlenecks", "", bearer)
	if rec.Code != http.StatusOK {
		t.Fatalf("код %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Bottlenecks []struct {
			Hostname string `json:"hostname"`
			Finding  struct {
				RuleID string `json:"rule_id"`
			} `json:"finding"`
		} `json:"bottlenecks"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("ответ: %v", err)
	}
	if len(resp.Bottlenecks) == 0 {
		t.Fatal("узкие места пусты при потерях 6%")
	}
	// При 6% срабатывают оба правила потерь; critical обязан быть.
	hasVeryHigh := false
	for _, b := range resp.Bottlenecks {
		if b.Finding.RuleID == "loss_very_high" {
			hasVeryHigh = true
		}
	}
	if !hasVeryHigh {
		t.Fatalf("loss_very_high не найден: %+v", resp.Bottlenecks)
	}
}

// Ряд: без параметров — 400; с параметрами — пустой ряд (фейк).
func TestQualitySeries(t *testing.T) {
	a := newRulesAPI(t, newFakeStore())
	if rec := do(a.Handler(), "GET", "/api/quality/series", "", bearer); rec.Code != http.StatusBadRequest {
		t.Fatalf("без параметров: код %d, хочу 400", rec.Code)
	}
	q := "/api/quality/series?agent=agent:one&target=192.168.1.1&kind=latency&from=" +
		time.Now().Add(-time.Hour).Format(time.RFC3339) + "&to=" + time.Now().Format(time.RFC3339)
	if rec := do(a.Handler(), "GET", q, "", bearer); rec.Code != http.StatusOK {
		t.Fatalf("ряд: код %d", rec.Code)
	}
	// 503 без движка.
	h := testAPI(t, newFakeStore(), &fakeProber{})
	if rec := do(h, "GET", "/api/quality/matrix", "", bearer); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("без движка: код %d, хочу 503", rec.Code)
	}
}
