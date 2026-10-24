// Правила узких мест сети (NR-008): пороги поверх метрик. Правила —
// rules/data/network.json (встроены, переопределяются --rules-dir).
// Каждое замечание: fact, threshold, source (цель и время).
package rules

import (
	"fmt"
	"sort"
	"time"
)

// Metric — одна точка метрик для оценки (из store.MetricAgg).
type Metric struct {
	Target string
	Kind   string
	Value  float64
	At     time.Time
}

// validateNetworkRule — те же требования, что и к правилам инвентаря.
func validateNetworkRule(r Rule) error { return validateRule(r) }

// EvaluateNetwork — замечания по метрикам одного агента.
func (e *Engine) EvaluateNetwork(metrics []Metric, now time.Time) []Finding {
	out := []Finding{}
	for _, r := range e.table.Network {
		switch r.ID {
		case "loss_high", "loss_very_high":
			out = append(out, e.lossRules(r, metrics, now)...)
		case "gateway_latency_high":
			out = append(out, e.gatewayLatency(r, metrics, now)...)
		case "jitter_high":
			out = append(out, e.jitterHigh(r, metrics, now)...)
		case "port_util_high":
			out = append(out, e.portUtil(r, metrics, now)...)
		case "port_errors":
			out = append(out, e.portCounter(r, metrics, "port_errors", now)...)
		case "port_discards":
			out = append(out, e.portCounter(r, metrics, "port_discards", now)...)
		case "bufferbloat_high":
			out = append(out, e.bufferbloat(r, metrics, now)...)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].RuleID != out[j].RuleID {
			return out[i].RuleID < out[j].RuleID
		}
		return out[i].Fact < out[j].Fact
	})
	return out
}

func netFinding(r Rule, fact, threshold string, m Metric, urgency float64) Finding {
	return Finding{
		RuleID: r.ID, Severity: r.Severity, Fact: fact, Threshold: threshold,
		Source: fmt.Sprintf("metrics.%s %s @ %s", m.Kind, m.Target, m.At.Format(time.RFC3339)),
		Advice: r.Advice, Priority: severityWeight(r.Severity) * Urgency(urgency),
	}
}

func (e *Engine) lossRules(r Rule, metrics []Metric, now time.Time) []Finding {
	limit := r.param("loss_percent", 2)
	out := []Finding{}
	for _, m := range metrics {
		if m.Kind != "loss" || m.Value <= limit/100 {
			continue
		}
		fact := fmt.Sprintf("потери до %s — %.1f%%", m.Target, m.Value*100)
		out = append(out, netFinding(r, fact, fmt.Sprintf("<= %.0f%%", limit), m, m.Value*100/2))
	}
	return out
}

func (e *Engine) gatewayLatency(r Rule, metrics []Metric, now time.Time) []Finding {
	limit := r.param("latency_ms", 50)
	out := []Finding{}
	for _, m := range metrics {
		if m.Kind != "latency" || m.Value <= limit {
			continue
		}
		fact := fmt.Sprintf("задержка до %s — %.0f мс", m.Target, m.Value)
		out = append(out, netFinding(r, fact, fmt.Sprintf("<= %.0f мс", limit), m, m.Value/20))
	}
	return out
}

func (e *Engine) jitterHigh(r Rule, metrics []Metric, now time.Time) []Finding {
	limit := r.param("jitter_ms", 30)
	out := []Finding{}
	for _, m := range metrics {
		if m.Kind != "jitter" || m.Value <= limit {
			continue
		}
		fact := fmt.Sprintf("джиттер до %s — %.0f мс", m.Target, m.Value)
		out = append(out, netFinding(r, fact, fmt.Sprintf("<= %.0f мс", limit), m, m.Value/10))
	}
	return out
}

func (e *Engine) portUtil(r Rule, metrics []Metric, now time.Time) []Finding {
	limit := r.param("util_percent", 80)
	out := []Finding{}
	for _, m := range metrics {
		if m.Kind != "port_util" || m.Value <= limit {
			continue
		}
		fact := fmt.Sprintf("порт %s загружен на %.0f%% в среднем за час", m.Target, m.Value)
		out = append(out, netFinding(r, fact, fmt.Sprintf("<= %.0f%%", limit), m, m.Value/20))
	}
	return out
}

func (e *Engine) portCounter(r Rule, metrics []Metric, kind string, now time.Time) []Finding {
	out := []Finding{}
	for _, m := range metrics {
		if m.Kind != kind || m.Value <= 0 {
			continue
		}
		var what string
		if kind == "port_errors" {
			what = "ошибок"
		} else {
			what = "отбросов"
		}
		fact := fmt.Sprintf("на порту %s — %.0f %s за интервал", m.Target, m.Value, what)
		out = append(out, netFinding(r, fact, "= 0", m, 3))
	}
	return out
}

func (e *Engine) bufferbloat(r Rule, metrics []Metric, now time.Time) []Finding {
	limit := r.param("bloat_ms", 100)
	out := []Finding{}
	for _, m := range metrics {
		if m.Kind != "bufferbloat" || m.Value <= limit {
			continue
		}
		fact := fmt.Sprintf("bufferbloat до %s — %.0f мс", m.Target, m.Value)
		out = append(out, netFinding(r, fact, fmt.Sprintf("<= %.0f мс", limit), m, m.Value/40))
	}
	return out
}

// SortedNetworkRules — правила узких мест в стабильном порядке.
func (e *Engine) SortedNetworkRules() []Rule {
	out := append([]Rule(nil), e.table.Network...)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
