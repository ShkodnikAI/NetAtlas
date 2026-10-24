// Тесты правил узких мест (NR-008): пороги на границах.
package rules

import (
	"testing"
	"time"
)

var netNow = time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)

func netEval(t *testing.T, metrics []Metric) []Finding {
	t.Helper()
	e := testEngine(t)
	return e.EvaluateNetwork(metrics, netNow)
}

func byRule(fs []Finding, id string) []Finding {
	out := []Finding{}
	for _, f := range fs {
		if f.RuleID == id {
			out = append(out, f)
		}
	}
	return out
}

// Потери: 2% — тихо, 3% — warning, 5% — только critical (не оба).
func TestNetLossThresholds(t *testing.T) {
	cases := []struct {
		loss         float64
		high, veryHi bool
	}{
		{0.02, false, false},
		{0.021, true, false},
		{0.03, true, false},
		{0.05, true, false}, // ровно 5% — граница, критично выше
		{0.051, true, true},
		{0.06, true, true},
	}
	for _, c := range cases {
		fs := netEval(t, []Metric{{Target: "gw", Kind: "loss", Value: c.loss, At: netNow}})
		if (len(byRule(fs, "loss_high")) > 0) != c.high {
			t.Fatalf("loss %.3f: loss_high %v, хочу %v", c.loss, len(byRule(fs, "loss_high")) > 0, c.high)
		}
		if (len(byRule(fs, "loss_very_high")) > 0) != c.veryHi {
			t.Fatalf("loss %.3f: loss_very_high %v, хочу %v", c.loss, len(byRule(fs, "loss_very_high")) > 0, c.veryHi)
		}
	}
}

// Задержка до шлюза: 50 мс — тихо, 51 — замечание.
func TestNetGatewayLatency(t *testing.T) {
	if fs := byRule(netEval(t, []Metric{{Target: "192.168.1.1", Kind: "latency", Value: 50, At: netNow}}), "gateway_latency_high"); len(fs) != 0 {
		t.Fatalf("ровно порог: %v", fs)
	}
	fs := byRule(netEval(t, []Metric{{Target: "192.168.1.1", Kind: "latency", Value: 51, At: netNow}}), "gateway_latency_high")
	if len(fs) != 1 || fs[0].Source == "" || fs[0].Fact == "" {
		t.Fatalf("выше порога: %+v", fs)
	}
}

// Джиттер: 30 — тихо, 31 — замечание.
func TestNetJitter(t *testing.T) {
	if fs := byRule(netEval(t, []Metric{{Target: "gw", Kind: "jitter", Value: 30, At: netNow}}), "jitter_high"); len(fs) != 0 {
		t.Fatalf("ровно порог: %v", fs)
	}
	if fs := byRule(netEval(t, []Metric{{Target: "gw", Kind: "jitter", Value: 31, At: netNow}}), "jitter_high"); len(fs) != 1 {
		t.Fatalf("выше порога: %v", fs)
	}
}

// Загрузка порта: 80% — тихо, 81% — замечание.
func TestNetPortUtil(t *testing.T) {
	if fs := byRule(netEval(t, []Metric{{Target: "port:5", Kind: "port_util", Value: 80, At: netNow}}), "port_util_high"); len(fs) != 0 {
		t.Fatalf("ровно порог: %v", fs)
	}
	if fs := byRule(netEval(t, []Metric{{Target: "port:5", Kind: "port_util", Value: 81, At: netNow}}), "port_util_high"); len(fs) != 1 {
		t.Fatalf("выше порога: %v", fs)
	}
}

// Ошибки и отбросы: ноль — тихо, рост — замечания.
func TestNetPortCounters(t *testing.T) {
	fs := netEval(t, []Metric{
		{Target: "port:5", Kind: "port_errors", Value: 0, At: netNow},
		{Target: "port:5", Kind: "port_discards", Value: 0, At: netNow},
	})
	if len(byRule(fs, "port_errors")) != 0 || len(byRule(fs, "port_discards")) != 0 {
		t.Fatalf("нули дали замечания: %v", fs)
	}
	fs = netEval(t, []Metric{
		{Target: "port:5", Kind: "port_errors", Value: 4, At: netNow},
		{Target: "port:5", Kind: "port_discards", Value: 2, At: netNow},
	})
	if len(byRule(fs, "port_errors")) != 1 || len(byRule(fs, "port_discards")) != 1 {
		t.Fatalf("рост не замечен: %v", fs)
	}
}

// Bufferbloat: 100 мс — тихо, 101 — замечание.
func TestNetBufferbloat(t *testing.T) {
	if fs := byRule(netEval(t, []Metric{{Target: "gw", Kind: "bufferbloat", Value: 100, At: netNow}}), "bufferbloat_high"); len(fs) != 0 {
		t.Fatalf("ровно порог: %v", fs)
	}
	if fs := byRule(netEval(t, []Metric{{Target: "gw", Kind: "bufferbloat", Value: 101, At: netNow}}), "bufferbloat_high"); len(fs) != 1 {
		t.Fatalf("выше порога: %v", fs)
	}
}

// Чужие kind не попадают в правила.
func TestNetForeignKinds(t *testing.T) {
	fs := netEval(t, []Metric{
		{Target: "gw", Kind: "latency", Value: 1000, At: netNow},
		{Target: "gw", Kind: "down_mbps", Value: 99999, At: netNow},
	})
	// Только latency-правило сработает (порог 50); down_mbps — нет
	// правил с этим kind.
	if len(byRule(fs, "loss_high")) != 0 || len(byRule(fs, "port_util_high")) != 0 {
		t.Fatalf("чужие kind попали в правила: %v", fs)
	}
}
