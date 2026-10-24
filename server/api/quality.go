// Экран «Качество сети» (NR-008): матрица «агент × цель», ряды
// агрегатов и узкие места по правилам сети.
package api

import (
	"net/http"
	"strings"
	"time"

	"github.com/ShkodnikAI/NetAtlas/rules"
	"github.com/ShkodnikAI/NetAtlas/server/store"
)

// ConfigureMetrics — глубина истории для правил (не нужна отдельно:
// правила берут последние значения).

// qualityTarget — состояние одной пары агент × цель.
type qualityTarget struct {
	AgentID string             `json:"agent_id"`
	Target  string             `json:"target"`
	Latest  map[string]float64 `json:"latest"` // kind → значение
	Worst   string             `json:"worst"`  // ok | warning | critical | info
}

// handleQualityMatrix — GET /api/quality/matrix.
func (a *API) handleQualityMatrix(w http.ResponseWriter, r *http.Request) {
	if err := a.rulesReady(w); err != nil {
		return
	}
	agents, err := a.store.ListAgents(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorBody{"список агентов"})
		return
	}
	now := time.Now()
	out := []qualityTarget{}
	for _, ag := range agents {
		latest, err := a.store.LatestMetrics(r.Context(), ag.ID)
		if err != nil || len(latest) == 0 {
			continue // нет данных — ячейки матрицы нет
		}
		metrics := toRuleMetrics(latest)
		findings := a.rules.EvaluateNetwork(metrics, now)
		worst := map[string]string{}
		for _, f := range findings {
			// Цель у замечания — в fact; связываем по правилу:
			// узкие места привязаны к цели в source.
			worst[f.Source] = worse(worst[f.Source], f.Severity)
		}
		qt := qualityTarget{AgentID: ag.ID, Latest: map[string]float64{}, Worst: "ok"}
		for _, m := range latest {
			if _, seen := qt.Latest[m.Kind]; !seen || m.Kind == "latency" {
				qt.Latest[m.Kind] = m.Avg
			}
			// Состояние цели: серьёзность замечаний по её метрикам.
			for src, sev := range worst {
				if strings.Contains(src, m.Target) {
					qt.Worst = worse(qt.Worst, sev)
				}
			}
		}
		out = append(out, qt)
	}
	writeJSON(w, http.StatusOK, map[string]any{"matrix": out})
}

// handleQualitySeries — GET /api/quality/series?agent=&target=&kind=&from=&to=&hourly=1
func (a *API) handleQualitySeries(w http.ResponseWriter, r *http.Request) {
	if err := a.rulesReady(w); err != nil {
		return
	}
	q := r.URL.Query()
	agent := q.Get("agent")
	target := q.Get("target")
	kind := q.Get("kind")
	if agent == "" || target == "" || kind == "" {
		writeJSON(w, http.StatusBadRequest, errorBody{"нужны agent, target и kind"})
		return
	}
	from, to := time.Now().Add(-24*time.Hour), time.Now()
	if f := q.Get("from"); f != "" {
		t, err := time.Parse(time.RFC3339, f)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, errorBody{"from: RFC3339"})
			return
		}
		from = t
	}
	if t := q.Get("to"); t != "" {
		p, err := time.Parse(time.RFC3339, t)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, errorBody{"to: RFC3339"})
			return
		}
		to = p
	}
	hourly := q.Get("hourly") == "1"
	series, err := a.store.SeriesMetrics(r.Context(), agent, target, kind, from, to, hourly)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorBody{"ряд метрик"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"series": series})
}

// handleQualityBottlenecks — GET /api/quality/bottlenecks: узкие
// места по всем агентам.
func (a *API) handleQualityBottlenecks(w http.ResponseWriter, r *http.Request) {
	if err := a.rulesReady(w); err != nil {
		return
	}
	agents, err := a.store.ListAgents(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorBody{"список агентов"})
		return
	}
	now := time.Now()
	type item struct {
		AgentID  string        `json:"agent_id"`
		Hostname string        `json:"hostname"`
		Finding  rules.Finding `json:"finding"`
	}
	out := []item{}
	for _, ag := range agents {
		latest, err := a.store.LatestMetrics(r.Context(), ag.ID)
		if err != nil || len(latest) == 0 {
			continue
		}
		for _, f := range a.rules.EvaluateNetwork(toRuleMetrics(latest), now) {
			out = append(out, item{AgentID: ag.ID, Hostname: ag.Hostname, Finding: f})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"bottlenecks": out})
}

// toRuleMetrics — агрегаты хранилища → точки правил.
func toRuleMetrics(agg []store.MetricAgg) []rules.Metric {
	out := make([]rules.Metric, 0, len(agg))
	for _, a := range agg {
		out = append(out, rules.Metric{Target: a.Target, Kind: a.Kind, Value: a.Avg, At: time.Now()})
	}
	return out
}

// worse — серьёзнее из двух.
func worse(a, b string) string {
	rank := map[string]int{"": 0, "info": 1, "warning": 2, "critical": 3}
	if rank[b] > rank[a] {
		return b
	}
	return a
}
