// Отчёты для ИИ (NR-013): сборка по теме из данных значениями,
// очистка, ответы как предложения, черновик из фрагмента, таблица
// соответствий только владельцу (в аудит). Провайдер вызывается
// из server/ai и только при ai_enabled.
package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/ShkodnikAI/NetAtlas/reports"
	"github.com/ShkodnikAI/NetAtlas/server/ai"
	"github.com/ShkodnikAI/NetAtlas/server/store"
)

// ConfigureAI — подключение провайдера (main.go): без вызова —
// ручной режим (ai_enabled=false).
func (a *API) ConfigureAI(p ai.Provider) { a.aiProvider = p }

// handleReportsList — GET /api/reports: список последних отчётов.
func (a *API) handleReportsList(w http.ResponseWriter, r *http.Request) {
	list, err := a.store.ListAIReports(r.Context())
	if err != nil {
		failScripts(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"reports": list})
}

// reportTopicBody — тело POST /api/reports.
type reportTopicBody struct {
	Topic    string `json:"topic"` // slow_network | disk_full | security | custom
	AgentID  string `json:"agent_id,omitempty"`
	Question string `json:"question,omitempty"`
}

// handleReportCreate — POST /api/reports: сборка отчёта по теме из
// данных (значениями) и очистка. Таблица соответствий не отдаётся.
func (a *API) handleReportCreate(w http.ResponseWriter, r *http.Request) {
	var body reportTopicBody
	if err := decodeJSON(r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{err.Error()})
		return
	}
	in, err := a.buildReportInput(r.Context(), body.Topic, body.AgentID, body.Question)
	if err != nil {
		failScripts(w, err)
		return
	}
	// Значения об устройстве попадают в контекст отчёта и
	// очищаются Sanitize'ом: имена заменяются псевдонимами,
	// таблица соответствий остаётся только у владельца.
	agent := a.reportAgent(r.Context(), body.AgentID)
	names := a.reportNameSource(agent)
	if agent != nil {
		appendAgentContext(in, agent)
	}
	rep, err := reports.Build(*in)
	if err != nil {
		failScripts(w, err)
		return
	}
	// Пометка внедрений до очистки: фраза-инъекция из данных
	// остаётся видимой под тегом [POSSIBLE_INJECTION] и не гасится
	// заменой на псевдоним.
	marked, warnings := reports.MarkInjections(rep.Render())
	cleaned, mapping := reports.Sanitize(marked, names)
	id, err := a.store.CreateAIReport(r.Context(), rep.Topic, cleaned, mappingEntries(mapping))
	if err != nil {
		failScripts(w, err)
		return
	}
	if len(warnings) > 0 {
		detail, _ := json.Marshal(map[string]any{"report": id, "warnings": warnings})
		_ = a.store.AppendAudit(r.Context(), "server", "report_injection_warning", strconv.FormatInt(id, 10), string(detail))
	}
	_ = a.store.AppendAudit(r.Context(), ActorOwner, "report_create", strconv.FormatInt(id, 10), "тема "+rep.Topic)
	writeJSON(w, http.StatusCreated, map[string]any{
		"id": id, "text": cleaned, "warnings": warnings,
	})
}

// mappingEntries — таблица для хранения.
func mappingEntries(m *reports.Mapping) []store.MappingRow {
	if m == nil {
		return nil
	}
	var out []store.MappingRow
	for _, e := range m.Entries() {
		out = append(out, store.MappingRow{Alias: e.Alias, Kind: e.Kind, Value: e.Value})
	}
	return out
}

// buildReportInput — сборка полей отчёта из данных (значениями).
func (a *API) buildReportInput(ctx context.Context, topic, agentID, question string) (*reports.Input, error) {
	in := &reports.Input{Topic: topic, Question: question}
	switch topic {
	case "slow_network":
		in.Observed = "Пользователь сообщает о медленном интернете на компьютере."
		in.Question = "Предложи безопасную последовательность диагностики (только предложение)."
		in.AlreadyChecked = []string{"Замеры качества сети агентом выполнены за сутки"}
		if agentID != "" {
			metrics, err := a.store.LatestMetrics(ctx, agentID)
			if err != nil {
				return nil, err
			}
			seen := map[string]float64{}
			var order []string
			for _, m := range metrics {
				key := m.Target + "/" + m.Kind
				if _, ok := seen[key]; !ok {
					order = append(order, key)
				}
				seen[key] = m.Avg
			}
			for _, key := range order {
				parts := splitKey(key)
				in.Measurements = append(in.Measurements, reports.Measurement{
					Name: "цель " + parts[0] + ", метрика " + parts[1], Value: seen[key],
				})
			}
		}
	case "disk_full":
		in.Observed = "Заполнение системного диска приближается к порогу."
		in.Question = "Предложи безопасную очистку без потери данных (только предложение)."
	case "security":
		in.Observed = "Замечания проверок безопасности требуют внимания."
		in.Question = "Предложи план устранения в порядке приоритета (только предложение)."
	default:
		in.Observed = "Запрос владельца."
	}
	return in, nil
}

func splitKey(k string) []string {
	if i := strings.IndexByte(k, '/'); i >= 0 {
		return []string{k[:i], k[i+1:]}
	}
	return []string{k, ""}
}

// reportAgent — агент по ID (значения): для контекста отчёта и
// справочника очистки. Ошибка списка не мешает отчёту — очистка
// работает и на пустом справочнике.
func (a *API) reportAgent(ctx context.Context, agentID string) *store.Agent {
	if agentID == "" {
		return nil
	}
	agents, err := a.store.ListAgents(ctx)
	if err != nil {
		return nil
	}
	for i := range agents {
		if agents[i].ID == agentID {
			return &agents[i]
		}
	}
	return nil
}

// appendAgentContext — значения об устройстве в контекст отчёта:
// имя и адаптеры (очистятся Sanitize'ом в псевдонимы).
func appendAgentContext(in *reports.Input, ag *store.Agent) {
	line := "Устройство из наблюдения: " + ag.Hostname
	if len(ag.MACList) > 0 {
		line += "; сетевые адаптеры: " + strings.Join(ag.MACList, ", ")
	}
	if in.Context != "" {
		in.Context += "; " + line
	} else {
		in.Context = line
	}
}

// reportNameSource — справочник имён для очистки: агенты и их хосты.
func (a *API) reportNameSource(agent *store.Agent) reports.NameSource {
	names := reports.NameSource{}
	agents, err := a.store.ListAgents(context.Background())
	if err == nil {
		for _, ag := range agents {
			if agent != nil && ag.ID != agent.ID {
				continue
			}
			if ag.Hostname != "" {
				names.Hosts = append(names.Hosts, ag.Hostname)
			}
			names.Hosts = append(names.Hosts, ag.ID)
			names.MACs = append(names.MACs, ag.MACList...)
		}
	}
	return names
}

// handleAIReport — GET /api/reports/{id}: очищенный текст (таблица
// соответствий не отдаётся).
func (a *API) handleAIReport(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r.PathValue("id"))
	if !ok {
		writeJSON(w, http.StatusBadRequest, errorBody{"id: число"})
		return
	}
	rep, err := a.store.AIReportByID(r.Context(), id)
	if err != nil {
		failScripts(w, err)
		return
	}
	writeJSON(w, http.StatusOK, rep)
}

// handleReportAnswer — POST /api/reports/{id}/answer: ответ ИИ как
// текст (лимит 32 КБ). Провайдер вызывается только при ai_enabled;
// в ручном режиме ответ вставляет владелец.
func (a *API) handleReportAnswer(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r.PathValue("id"))
	if !ok {
		writeJSON(w, http.StatusBadRequest, errorBody{"id: число"})
		return
	}
	var body struct {
		Text  string `json:"text,omitempty"`
		UseAI bool   `json:"use_ai,omitempty"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{err.Error()})
		return
	}
	answer := body.Text
	if body.UseAI {
		provider := a.aiProvider
		if provider == nil {
			provider = ai.ManualProvider{}
		}
		if provider.Name() == "manual" {
			writeJSON(w, http.StatusServiceUnavailable, errorBody{ai.ErrDisabled.Error()})
			return
		}
		rep, err := a.store.AIReportByID(r.Context(), id)
		if err != nil {
			failScripts(w, err)
			return
		}
		// Провайдер получает только строку очищенного отчёта.
		text, err := provider.Ask(r.Context(), rep.CleanedText)
		if err != nil {
			_ = a.store.AppendAudit(r.Context(), ActorOwner, "report_ai_error", strconv.FormatInt(id, 10), err.Error())
			writeJSON(w, http.StatusBadGateway, errorBody{err.Error()})
			return
		}
		answer = text
		_ = a.store.AppendAudit(r.Context(), ActorOwner, "report_ai_answer", strconv.FormatInt(id, 10), "провайдер "+provider.Name())
	}
	if err := a.store.SaveAIAnswer(r.Context(), id, answer); err != nil {
		failScripts(w, err)
		return
	}
	_ = a.store.AppendAudit(r.Context(), ActorOwner, "report_answer", strconv.FormatInt(id, 10), "ответ принят как предложение")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "answer": answer})
}

// handleReportDraft — POST /api/reports/{id}/draft: создать черновик
// скрипта из выбранного фрагмента ответа (всегда draft, NR-011).
// Из ответа не исполняется и не подписывается ничего.
func (a *API) handleReportDraft(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r.PathValue("id"))
	if !ok {
		writeJSON(w, http.StatusBadRequest, errorBody{"id: число"})
		return
	}
	var body struct {
		Name     string `json:"name"`
		Fragment string `json:"fragment"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{err.Error()})
		return
	}
	if body.Name == "" {
		writeJSON(w, http.StatusBadRequest, errorBody{"название черновика обязательно"})
		return
	}
	scriptID, versionID, err := a.store.CreateScript(r.Context(), store.CreateScriptInput{
		Name: body.Name, Kind: "script", Category: "general", Content: body.Fragment,
	}, ActorOwner)
	if err != nil {
		failScripts(w, err)
		return
	}
	_ = a.store.AppendAudit(r.Context(), ActorOwner, "report_draft",
		strconv.FormatInt(id, 10), fmt.Sprintf("черновик скрипта %d (версия %d, draft)", scriptID, versionID))
	writeJSON(w, http.StatusCreated, map[string]int64{"script_id": scriptID, "version_id": versionID})
}

// handleReportMapping — GET /api/reports/{id}/mapping: таблица
// соответствий только владельцу (в аудит).
func (a *API) handleReportMapping(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r.PathValue("id"))
	if !ok {
		writeJSON(w, http.StatusBadRequest, errorBody{"id: число"})
		return
	}
	mapping, err := a.store.AIMapping(r.Context(), id)
	if err != nil {
		failScripts(w, err)
		return
	}
	if err := a.store.AppendAudit(r.Context(), ActorOwner, "report_mapping_view",
		strconv.FormatInt(id, 10), "просмотр таблицы соответствий"); err != nil {
		writeJSON(w, http.StatusInternalServerError, errorBody{"аудит"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"mapping": mapping})
}
