// Маршруты владельца для активности сотрудников (NR-012): включение
// с фразой подтверждения, выключение, просмотр (каждый запрос в
// аудит), удаление собранного. Сбор по умолчанию выключен.
package api

import (
	"context"
	"net/http"
	"strconv"
	"time"
)

// activitySummaryMaxDays — предел периода запроса (год).
const activitySummaryMaxDays = 366

// handleActivityEnable — POST /api/activity/enable: включение сбора
// для ПК. Требует точную фразу подтверждения — сервер откажет без
// неё; запись подтверждения попадает в аудит (store).
func (a *API) handleActivityEnable(w http.ResponseWriter, r *http.Request) {
	var body struct {
		AgentID      string `json:"agent_id"`
		Confirmation string `json:"confirmation"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{err.Error()})
		return
	}
	if err := a.store.EnableActivity(r.Context(), body.AgentID, body.Confirmation, ActorOwner); err != nil {
		failScripts(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// handleActivityDisable — POST /api/activity/disable: выключение
// сбора для ПК (в аудит).
func (a *API) handleActivityDisable(w http.ResponseWriter, r *http.Request) {
	var body struct {
		AgentID string `json:"agent_id"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{err.Error()})
		return
	}
	if err := a.store.DisableActivity(r.Context(), body.AgentID, ActorOwner); err != nil {
		failScripts(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// handleActivityComputers — GET /api/activity/computers: ПК с
// включённым сбором. Запрос владельца — в аудит.
func (a *API) handleActivityComputers(w http.ResponseWriter, r *http.Request) {
	list, err := a.store.ListActivityEnabled(r.Context())
	if err != nil {
		failScripts(w, err)
		return
	}
	if err := a.store.AppendAudit(r.Context(), ActorOwner, "activity_view", "computers", "просмотр списка ПК со сбором активности"); err != nil {
		writeJSON(w, http.StatusInternalServerError, errorBody{"аудит"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"computers": list})
}

// handleActivitySummary — GET /api/activity/summary: агрегации за
// период. Каждый запрос владельца пишет в аудит (приватность).
func (a *API) handleActivitySummary(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	from := time.Now().AddDate(0, 0, -1)
	to := time.Now()
	if raw := q.Get("from"); raw != "" {
		t, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, errorBody{"from: формат RFC3339"})
			return
		}
		from = t
	}
	if raw := q.Get("to"); raw != "" {
		t, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, errorBody{"to: формат RFC3339"})
			return
		}
		to = t
	}
	if to.Before(from) || to.Sub(from) > activitySummaryMaxDays*24*time.Hour {
		writeJSON(w, http.StatusBadRequest, errorBody{"период: до 1 года, to после from"})
		return
	}
	agentID, account := q.Get("computer"), q.Get("account")
	sum, err := a.store.ActivityAggregates(r.Context(), from, to, agentID, account)
	if err != nil {
		failScripts(w, err)
		return
	}
	detail := "просмотр активности"
	if agentID != "" {
		detail += ", компьютер " + agentID
	}
	if account != "" {
		detail += ", учётная запись " + account
	}
	if err := a.store.AppendAudit(r.Context(), ActorOwner, "activity_view", "summary", detail); err != nil {
		writeJSON(w, http.StatusInternalServerError, errorBody{"аудит"})
		return
	}
	writeJSON(w, http.StatusOK, sum)
}

// handleActivityPurge — DELETE /api/activity?computer=: удалить
// собранное по ПК (запрос владельца, в аудит).
func (a *API) handleActivityPurge(w http.ResponseWriter, r *http.Request) {
	agentID := r.URL.Query().Get("computer")
	if agentID == "" {
		writeJSON(w, http.StatusBadRequest, errorBody{"computer: идентификатор агента обязателен"})
		return
	}
	n, err := a.store.DeleteActivityFor(r.Context(), agentID, ActorOwner)
	if err != nil {
		failScripts(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "rows": n})
}

// PurgeActivityNow — разовая чистка старше 90 дней с записью в
// аудит. Вызывается фоновым циклом сервера раз в сутки; ошибка не
// роняет сервер.
func (a *API) PurgeActivityNow(ctx context.Context) {
	n, err := a.store.PurgeOldActivity(ctx, time.Now())
	if err != nil {
		return
	}
	if n > 0 {
		detail := "удалено записей: " + strconv.FormatInt(n, 10)
		_ = a.store.AppendAudit(ctx, "server", "activity_purge_expired", "90 дней", detail)
	}
}
