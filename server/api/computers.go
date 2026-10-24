// Экраны «Компьютеры» и «Диски» (NR-009): сводка по агентам с
// замечаниями движка правил и прогнозом заполнения дисков. Без
// настроенных правил (ConfigureRules) маршруты отвечают 503.
package api

import (
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ShkodnikAI/NetAtlas/agent/collect"
	"github.com/ShkodnikAI/NetAtlas/rules"
	"github.com/ShkodnikAI/NetAtlas/server/store"
)

// ConfigureRules подключает движок правил (cmd делает это на старте).
func (a *API) ConfigureRules(re *rules.Engine) {
	a.rules = re
}

// historyDays — глубина истории для прогноза (наряд: 30 дней).
const historyDays = 30

// computerSummary — строка списка «Компьютеры».
type computerSummary struct {
	ID              string         `json:"id"`
	Hostname        string         `json:"hostname"`
	Status          string         `json:"status"`
	LastSeen        *time.Time     `json:"last_seen,omitempty"`
	InventoryAt     string         `json:"inventory_at,omitempty"`
	Findings        map[string]int `json:"findings,omitempty"`
	MaxPriority     float64        `json:"max_priority,omitempty"`
	WorstDaysToFull *int           `json:"worst_days_to_full,omitempty"`
}

// handleComputers — GET /api/computers: сводка по всем агентам.
func (a *API) handleComputers(w http.ResponseWriter, r *http.Request) {
	if err := a.rulesReady(w); err != nil {
		return
	}
	agents, err := a.store.ListAgents(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorBody{"список агентов"})
		return
	}
	now := time.Now()
	out := []computerSummary{}
	for _, ag := range agents {
		s := computerSummary{ID: ag.ID, Hostname: ag.Hostname, Status: ag.Status}
		if !ag.LastSeen.IsZero() {
			s.LastSeen = &ag.LastSeen
		}
		inv, err := a.store.LatestInventory(r.Context(), ag.ID)
		if err == nil {
			s.InventoryAt = inv.CollectedAt.Format(time.RFC3339)
			rep := reportOf(inv)
			if rep != nil {
				findings := a.rules.Evaluate(rep, now)
				s.Findings = countBySeverity(findings)
				for _, f := range findings {
					if f.Priority > s.MaxPriority {
						s.MaxPriority = f.Priority
					}
				}
				worst := a.worstDaysToFull(r, ag.ID, rep, now)
				s.WorstDaysToFull = worst
			}
		}
		out = append(out, s)
	}
	writeJSON(w, http.StatusOK, map[string]any{"computers": out})
}

// computerCard — карточка GET /api/computers/{id}.
type computerCard struct {
	ID          string                    `json:"id"`
	Hostname    string                    `json:"hostname"`
	Status      string                    `json:"status"`
	Inventory   *collect.Report           `json:"inventory,omitempty"`
	Findings    []rules.Finding           `json:"findings,omitempty"`
	Forecasts   map[string]rules.Forecast `json:"forecasts,omitempty"`
	InventoryAt string                    `json:"inventory_at,omitempty"`
}

// handleComputer — GET /api/computers/{id}: инвентарь, замечания,
// прогнозы по томам.
func (a *API) handleComputer(w http.ResponseWriter, r *http.Request) {
	if err := a.rulesReady(w); err != nil {
		return
	}
	id := r.PathValue("id")
	ag, err := a.store.AgentByID(r.Context(), id)
	if err != nil {
		fail(w, err)
		return
	}
	card := computerCard{ID: ag.ID, Hostname: ag.Hostname, Status: ag.Status}
	inv, err := a.store.LatestInventory(r.Context(), id)
	if err == nil {
		card.InventoryAt = inv.CollectedAt.Format(time.RFC3339)
		card.Inventory = reportOf(inv)
	}
	if card.Inventory != nil {
		card.Findings = a.rules.Evaluate(card.Inventory, time.Now())
		card.Forecasts = a.forecasts(r, id, card.Inventory)
	}
	writeJSON(w, http.StatusOK, card)
}

// diskView — строка GET /api/disks.
type diskView struct {
	AgentID    string         `json:"agent_id"`
	Hostname   string         `json:"hostname"`
	Drive      string         `json:"drive"`
	Label      string         `json:"label,omitempty"`
	FileSystem string         `json:"file_system,omitempty"`
	Capacity   float64        `json:"capacity_bytes"`
	Used       float64        `json:"used_bytes"`
	FreePct    float64        `json:"free_pct"`
	Forecast   rules.Forecast `json:"forecast"`
}

// handleDisks — GET /api/disks: все тома всех агентов с заполнением
// и прогнозом.
func (a *API) handleDisks(w http.ResponseWriter, r *http.Request) {
	if err := a.rulesReady(w); err != nil {
		return
	}
	agents, err := a.store.ListAgents(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorBody{"список агентов"})
		return
	}
	out := []diskView{}
	for _, ag := range agents {
		inv, err := a.store.LatestInventory(r.Context(), ag.ID)
		if err != nil {
			continue // нет данных — томов нет
		}
		rep := reportOf(inv)
		if rep == nil || rep.Disks == nil {
			continue
		}
		forecasts := a.forecasts(r, ag.ID, rep)
		for _, v := range rep.Disks.Volumes {
			if v.DriveLetter == "" {
				continue
			}
			size := parseBytes(v.Size)
			free := parseBytes(v.SizeRemaining)
			if size <= 0 {
				continue
			}
			dv := diskView{
				AgentID: ag.ID, Hostname: ag.Hostname, Drive: v.DriveLetter,
				Label: v.Label, FileSystem: v.FileSystem,
				Capacity: size, Used: size - free,
				FreePct:  free / size * 100,
				Forecast: forecasts[v.DriveLetter],
			}
			out = append(out, dv)
		}
	}
	// Детерминированный порядок: хост, том.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Hostname != out[j].Hostname {
			return out[i].Hostname < out[j].Hostname
		}
		return out[i].Drive < out[j].Drive
	})
	writeJSON(w, http.StatusOK, map[string]any{"disks": out})
}

// --- вспомогательные -------------------------------------------------------

// rulesReady — 503, если движок правил не подключён.
func (a *API) rulesReady(w http.ResponseWriter) error {
	if a.rules == nil {
		writeJSON(w, http.StatusServiceUnavailable, errorBody{"правила не настроены на сервере"})
		return errStop
	}
	return nil
}

// errStop — маркер «ответ уже написан».
var errStop = &stopError{}

type stopError struct{}

func (*stopError) Error() string { return "стоп" }

// reportOf — отчёт из последней порции инвентаря (nil, если не v1).
func reportOf(inv store.InventoryRow) *collect.Report {
	if inv.JSON == "" {
		return nil
	}
	var env struct {
		Payload json.RawMessage `json:"payload"`
	}
	if err := json.Unmarshal([]byte(inv.JSON), &env); err != nil {
		return nil
	}
	var rep collect.Report
	if err := json.Unmarshal(env.Payload, &rep); err != nil {
		return nil
	}
	if rep.InventorySchemaVersion != collect.SchemaVersion {
		return nil
	}
	return &rep
}

// countBySeverity — счётчик замечаний по серьёзности.
func countBySeverity(fs []rules.Finding) map[string]int {
	m := map[string]int{}
	for _, f := range fs {
		m[f.Severity]++
	}
	return m
}

// forecasts — прогнозы по всем томам карточки.
func (a *API) forecasts(r *http.Request, agentID string, rep *collect.Report) map[string]rules.Forecast {
	out := map[string]rules.Forecast{}
	if rep.Disks == nil {
		return out
	}
	for _, v := range rep.Disks.Volumes {
		if v.DriveLetter == "" {
			continue
		}
		points, err := a.store.DiskHistory(r.Context(), agentID, v.DriveLetter, historyDays)
		if err != nil {
			out[v.DriveLetter] = rules.Forecast{Insufficient: "история недоступна"}
			continue
		}
		rp := make([]rules.Point, 0, len(points))
		for _, p := range points {
			rp = append(rp, rules.Point{
				Day: p.Day.Format("2006-01-02"), Used: float64(p.Used), Capacity: float64(p.Capacity),
			})
		}
		// Свежая точка (сегодняшний отчёт) — поверх истории.
		today := time.Now().UTC().Format("2006-01-02")
		used := parseBytes(v.Size) - parseBytes(v.SizeRemaining)
		if used > 0 && parseBytes(v.Size) > 0 {
			rp = append(rp, rules.Point{Day: today, Used: used, Capacity: parseBytes(v.Size)})
		}
		out[v.DriveLetter] = rules.ForecastDisk(rp)
	}
	return out
}

// worstDaysToFull — минимум days_to_full по томам (nil — никто не
// переполнится или данных мало).
func (a *API) worstDaysToFull(r *http.Request, agentID string, rep *collect.Report, now time.Time) *int {
	if rep.Disks == nil {
		return nil
	}
	forecasts := a.forecasts(r, agentID, rep)
	var worst *int
	for _, f := range forecasts {
		if f.DaysToFull == nil {
			continue
		}
		if worst == nil || *f.DaysToFull < *worst {
			v := *f.DaysToFull
			worst = &v
		}
	}
	return worst
}

// parseBytes — число байт строкой; мусор — 0.
func parseBytes(s string) float64 {
	n, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil {
		return 0
	}
	return n
}
