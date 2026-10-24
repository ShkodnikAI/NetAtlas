// Экран «Безопасность» (NR-010): сводка замечаний по отчётам
// проверок агентов, инвентарю (ОС, ПО) и сетевым наблюдениям
// сканера. Оценка считается по правилам и весам (rules/security),
// без участия ИИ. Только чтение: маршруты ничего не меняют.
package api

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/ShkodnikAI/NetAtlas/agent/checks"
	"github.com/ShkodnikAI/NetAtlas/agent/collect"
	"github.com/ShkodnikAI/NetAtlas/rules/security"
)

// securityGroup — агрегированное замечание сводки: одно правило со
// списком компьютеров (как в макете design/Security.dc.html).
type securityGroup struct {
	RuleID   string   `json:"rule_id"`
	Severity string   `json:"severity"`
	Title    string   `json:"title"`
	Basis    string   `json:"basis"`
	BasisURL string   `json:"basis_url,omitempty"`
	Advice   string   `json:"advice"`
	Weight   int      `json:"weight"`
	Where    []string `json:"where"`
}

// securityComputerRow — строка компьютера в сводке.
type securityComputerRow struct {
	ID       string `json:"id"`
	Hostname string `json:"hostname"`
	Score    int    `json:"score"`
	Worst    string `json:"worst"` // critical | warning | info | ok | unknown
	Unknown  int    `json:"unknown_checks"`
}

// securitySummary — ответ GET /api/security/summary.
type securitySummary struct {
	Score         *int                  `json:"score"` // null — нет данных, не «всё безопасно»
	GeneratedAt   string                `json:"generated_at"`
	Counts        map[string]int        `json:"counts"`
	UnknownChecks int                   `json:"unknown_checks"`
	Computers     []securityComputerRow `json:"computers"`
	Findings      []securityGroup       `json:"findings"`
	Network       []securityGroup       `json:"network"`
}

// handleSecuritySummary — GET /api/security/summary.
func (a *API) handleSecuritySummary(w http.ResponseWriter, r *http.Request) {
	if err := a.rulesReady(w); err != nil {
		return
	}
	agents, err := a.store.ListAgents(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorBody{"список агентов"})
		return
	}
	sec := security.NewEngine(a.rules)
	now := time.Now()

	out := securitySummary{
		GeneratedAt: now.UTC().Format(time.RFC3339),
		Counts:      map[string]int{"critical": 0, "warning": 0, "info": 0},
		Computers:   []securityComputerRow{},
		Findings:    []securityGroup{},
		Network:     []securityGroup{},
	}
	groups := map[string]*securityGroup{}
	scores := []int{}

	for _, ag := range agents {
		res, known := a.agentSecurity(r, sec, ag.ID, ag.Hostname, now)
		if !known {
			continue // нет ни отчёта проверок, ни инвентаря — данных нет
		}
		out.Computers = append(out.Computers, res.Row)
		if res.Row.Unknown > 0 {
			out.UnknownChecks += res.Row.Unknown
		}
		for _, f := range res.Findings {
			out.Counts[f.Severity]++
			g := groups[f.RuleID]
			if g == nil {
				g = &securityGroup{
					RuleID:   f.RuleID,
					Severity: f.Severity,
					Title:    titleOf(sec, f),
					Basis:    f.Basis,
					BasisURL: f.BasisURL,
					Advice:   f.Advice,
					Weight:   f.Weight,
					Where:    []string{},
				}
				groups[f.RuleID] = g
			}
			if !containsString(g.Where, ag.Hostname) {
				g.Where = append(g.Where, ag.Hostname)
			}
		}
		// Любой компьютер с данными участвует в общей оценке:
		// машина с критичной ОС без отчёта тоже снижает среднее.
		scores = append(scores, res.Row.Score)
	}
	for _, g := range groups {
		out.Findings = append(out.Findings, *g)
	}
	sortGroups(out.Findings)

	// Сетевые замечания — из наблюдений сканера (без новых проб).
	devs, err := a.store.ListDevices(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorBody{"устройства"})
		return
	}
	nd := make([]security.NetworkDevice, 0, len(devs))
	for _, d := range devs {
		sources := make([]string, 0, len(d.Observations))
		for _, o := range d.Observations {
			sources = append(sources, o.Source)
		}
		label := d.Hostname
		if label == "" {
			label = d.Vendor
		}
		nd = append(nd, security.NetworkDevice{ID: d.ID, Label: label, Klass: string(d.Class), Sources: sources})
	}
	for _, f := range sec.EvaluateNetwork(nd) {
		out.Network = append(out.Network, securityGroup{
			RuleID:   f.RuleID,
			Severity: f.Severity,
			Title:    f.Fact,
			Basis:    f.Basis,
			BasisURL: f.BasisURL,
			Advice:   f.Advice,
			Weight:   f.Weight,
			Where:    []string{whereOf(f.Source)},
		})
	}

	// Общая оценка: среднее по компьютерам с отчётами проверок
	// (округление вниз); без данных — null, а не «всё безопасно».
	if len(scores) > 0 {
		total := 0
		for _, s := range scores {
			total += s
		}
		mean := total / len(scores)
		out.Score = &mean
	}
	writeJSON(w, http.StatusOK, out)
}

// securityResult — итог разбора данных одного агента.
type securityResult struct {
	Row      securityComputerRow
	Findings []security.Finding
}

// agentSecurity — сводка по одному агенту: отчёт проверок
// (POST /agent/v1/security), замечания инвентаря из таблицы весов
// (например, os_out_of_support) и ПО против таблицы версий.
func (a *API) agentSecurity(r *http.Request, sec *security.Engine, agentID, hostname string, now time.Time) (securityResult, bool) {
	res := securityResult{
		Row: securityComputerRow{ID: agentID, Hostname: hostname, Score: 100, Worst: "ok"},
	}
	var findings []security.Finding
	var rep *collect.Report
	collected := ""

	if sr, err := a.store.LatestSecurity(r.Context(), agentID); err == nil {
		collected = sr.CollectedAt.Format(time.RFC3339)
		var env struct {
			Results []checks.Result `json:"results"`
		}
		if err := json.Unmarshal([]byte(sr.JSON), &env); err == nil {
			findings = append(findings, sec.EvaluateChecks(env.Results, agentID, collected)...)
			res.Row.Unknown = countUnknown(env.Results)
		}
	}

	// Замечания обычного вычислителя правил, входящие в таблицу
	// весов безопасности (os_out_of_support), переиспользуются:
	// логика сроков ОС одна, веса для оценки — свои.
	if inv, err := a.store.LatestInventory(r.Context(), agentID); err == nil {
		if cr := reportOf(inv); cr != nil {
			rep = cr
			for _, f := range a.rules.Evaluate(cr, now) {
				if s, ok := sec.Rule(f.RuleID); ok {
					findings = append(findings, security.Finding{
						RuleID:   f.RuleID,
						Severity: f.Severity,
						Fact:     f.Fact,
						Source:   f.Source,
						Advice:   s.Advice,
						Basis:    s.Basis,
						BasisURL: s.BasisURL,
						Weight:   s.Weight,
						Priority: f.Priority,
					})
				}
			}
			progs := make([]security.Software, 0, len(rep.Programs))
			for _, p := range rep.Programs {
				progs = append(progs, security.Software{Name: p.Name, Version: p.Version})
			}
			findings = append(findings, sec.EvaluateSoftware(progs, agentID, collected)...)
		}
	}

	if len(findings) > 0 {
		res.Row.Score = sec.Score(findings)
		for _, f := range findings {
			res.Row.Worst = worse(f.Severity, res.Row.Worst)
		}
	}
	res.Findings = findings
	known := collected != "" || rep != nil
	if !known {
		res.Row.Worst = "unknown"
	}
	return res, known
}

// securityCard — ответ GET /api/security/computers/{id}.
type securityCard struct {
	ID          string             `json:"id"`
	Hostname    string             `json:"hostname"`
	Score       *int               `json:"score"`
	CollectedAt string             `json:"collected_at,omitempty"`
	Checks      []checks.Result    `json:"checks"`
	Findings    []security.Finding `json:"findings"`
	Ports       []portEntry        `json:"ports,omitempty"`
}

// portEntry — слушающий порт из данных проверки ports.
type portEntry struct {
	LocalAddress string `json:"local_address"`
	LocalPort    int    `json:"local_port"`
	Process      string `json:"process,omitempty"`
}

// handleSecurityComputer — GET /api/security/computers/{id}:
// карточка безопасности компьютера.
func (a *API) handleSecurityComputer(w http.ResponseWriter, r *http.Request) {
	if err := a.rulesReady(w); err != nil {
		return
	}
	id := r.PathValue("id")
	ag, err := a.store.AgentByID(r.Context(), id)
	if err != nil {
		fail(w, err)
		return
	}
	sec := security.NewEngine(a.rules)
	res, known := a.agentSecurity(r, sec, ag.ID, ag.Hostname, time.Now())
	if !known {
		writeJSON(w, http.StatusNotFound, errorBody{"по агенту нет ни отчёта проверок, ни инвентаря"})
		return
	}
	card := securityCard{
		ID:       ag.ID,
		Hostname: ag.Hostname,
		Score:    &res.Row.Score,
		Checks:   []checks.Result{},
		Findings: res.Findings,
		Ports:    []portEntry{},
	}
	if sr, err := a.store.LatestSecurity(r.Context(), id); err == nil {
		card.CollectedAt = sr.CollectedAt.Format(time.RFC3339)
		var env struct {
			Results []checks.Result `json:"results"`
		}
		if err := json.Unmarshal([]byte(sr.JSON), &env); err == nil {
			card.Checks = env.Results
			for _, chk := range env.Results {
				if chk.ID != checks.CheckPorts || chk.Status != checks.StatusPass || len(chk.Data) == 0 {
					continue
				}
				var data struct {
					Ports []portEntry `json:"ports"`
				}
				if err := json.Unmarshal(chk.Data, &data); err == nil {
					card.Ports = append(card.Ports, data.Ports...)
				}
			}
		}
	}
	writeJSON(w, http.StatusOK, card)
}

// countUnknown — число проверок со статусом unknown в отчёте.
func countUnknown(results []checks.Result) int {
	n := 0
	for _, res := range results {
		if res.Status == checks.StatusUnknown {
			n++
		}
	}
	return n
}

// titleOf — заголовок правила из таблицы весов; нет записи — факт.
func titleOf(sec *security.Engine, f security.Finding) string {
	if s, ok := sec.Rule(f.RuleID); ok && s.Title != "" {
		return s.Title
	}
	return f.Fact
}

// whereOf — цель сетевого замечания из источника («scan:observations X»).
func whereOf(source string) string {
	if _, target, ok := strings.Cut(source, "scan:observations "); ok {
		return target
	}
	return source
}

// containsString — есть ли значение в срезе.
func containsString(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// sortGroups — детерминированный порядок групп: худшие сверху,
// внутри — вес, правило.
func sortGroups(gs []securityGroup) {
	rank := map[string]int{"critical": 0, "warning": 1, "info": 2}
	sort.Slice(gs, func(i, j int) bool {
		if gs[i].Severity != gs[j].Severity {
			return rank[gs[i].Severity] < rank[gs[j].Severity]
		}
		if gs[i].Weight != gs[j].Weight {
			return gs[i].Weight > gs[j].Weight
		}
		return gs[i].RuleID < gs[j].RuleID
	})
}
