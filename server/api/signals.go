// Сигналы внимания на карте (NR-033 п.4): вычисление из уже
// собранных данных — сеть не расходуется. Источники: открытые
// оповещения о новых неизвестных устройствах (NR-005), долгое
// молчание устройства, находки правил безопасности и качества,
// окончание поддержки ОС (Windows 10), один IP у нескольких MAC,
// разрыв журнала аудита. Отложенные решения («Игнорировать на N
// дней») хранятся в хранилище и прячут сигнал до срока.

package api

import (
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/ShkodnikAI/NetAtlas/agent/collect"
	"github.com/ShkodnikAI/NetAtlas/rules"
	"github.com/ShkodnikAI/NetAtlas/rules/security"
	"github.com/ShkodnikAI/NetAtlas/server/store"
)

// Виды сигналов (kind).
const (
	SignalUnknownNew = "unknown_new" // новое неизвестное устройство (оповещение NR-005)
	SignalNoResponse = "no_response" // не отвечает дольше порога
	SignalSecurity   = "security"    // находка правил безопасности
	SignalQuality    = "quality"     // находка правил качества сети
	SignalOS_EOL     = "eol"         // окончание поддержки ОС
	SignalIPConflict = "ip_conflict" // один IP у нескольких MAC
	SignalAuditGap   = "audit_gap"   // разрыв журнала аудита
)

// Статусы узла карты: маркеры ● ▲ ■ ○ ◇ (NR-033 п.2).
const (
	NodeOnline     = "online"     // ● в сети
	NodeAttention  = "attention"  // ▲ внимание
	NodeProblem    = "problem"    // ■ проблема
	NodeOffline    = "offline"    // ○ не в сети
	NodeUnverified = "unverified" // ◇ не проверен
)

// noResponseThreshold — порог молчания: устройство не отвечает
// дольше суток. Предположение (наряд не задаёт значение): сутки
// достаточно, чтобы считать домашний/офисный узел выключенным.
const noResponseThreshold = 24 * time.Hour

// mapSignal — один сигнал внимания.
type mapSignal struct {
	DeviceID string `json:"device_id"` // "" — сигнал уровня карты (журнал аудита)
	Status   string `json:"status"`    // problem | attention | offline
	Kind     string `json:"kind"`
	Text     string `json:"text"`
	Decision bool   `json:"decision"` // требуется решение владельца
}

// nodeStatus — сводный статус узла для значка-бейджа.
type nodeStatus struct {
	ID        string `json:"id"`
	Status    string `json:"status"`
	Decisions int    `json:"decisions"`
}

// signalsResponse — ответ GET /api/signals.
type signalsResponse struct {
	Signals  []mapSignal  `json:"signals"`
	Statuses []nodeStatus `json:"statuses"`
}

// handleSignals — GET /api/signals: сигналы внимания и сводные
// статусы узлов. Правила безопасности и качества считаются лучшими
// усилиями: без настроенного движка правил остальные сигналы
// продолжают работать.
func (a *API) handleSignals(w http.ResponseWriter, r *http.Request) {
	now := time.Now()
	devs, err := a.store.SignalDevices(r.Context())
	if err != nil {
		fail(w, err)
		return
	}
	alerts, err := a.store.OpenAlerts(r.Context())
	if err != nil {
		fail(w, err)
		return
	}
	snoozed, err := a.store.ActiveSnoozes(r.Context(), now)
	if err != nil {
		fail(w, err)
		return
	}
	agentsByMAC, err := a.store.AgentsByMAC(r.Context())
	if err != nil {
		fail(w, err)
		return
	}

	signals := []mapSignal{}
	add := func(s mapSignal) {
		if snoozed[s.DeviceID+"\x00"+s.Kind] {
			return
		}
		signals = append(signals, s)
	}

	// Новые неизвестные устройства (оповещения NR-005): требуется
	// решение владельца — принять, игнорировать, отложить.
	for _, al := range alerts {
		add(mapSignal{
			DeviceID: al.DeviceID,
			Status:   NodeAttention,
			Kind:     SignalUnknownNew,
			Text:     "Новое неизвестное устройство: подтвердите, что это ваше",
			Decision: true,
		})
	}

	// Долгое молчание: устройство не отвечает дольше порога.
	for _, d := range devs {
		if d.Manual || d.LastSeen.IsZero() {
			continue
		}
		if now.Sub(d.LastSeen) > noResponseThreshold {
			add(mapSignal{
				DeviceID: d.ID,
				Status:   NodeOffline,
				Kind:     SignalNoResponse,
				Text:     "Не отвечает дольше суток: последнее обнаружение " + d.LastSeen.Format("02.01.2006 15:04"),
			})
		}
	}

	// Один IP у нескольких MAC: смена MAC у адреса или конфликт.
	owners := map[string][]string{}
	for _, d := range devs {
		for _, ip := range d.IPs {
			owners[ip] = append(owners[ip], d.ID)
		}
	}
	conflictIPs := map[string]bool{}
	for ip, ids := range owners {
		if len(ids) > 1 {
			conflictIPs[ip] = true
		}
	}
	for _, d := range devs {
		for _, ip := range d.IPs {
			if !conflictIPs[ip] {
				continue
			}
			others := []string{}
			for _, other := range owners[ip] {
				if other != d.ID {
					others = append(others, other)
				}
			}
			add(mapSignal{
				DeviceID: d.ID,
				Status:   NodeAttention,
				Kind:     SignalIPConflict,
				Text:     "Адрес " + ip + " закреплён ещё и за " + strings.Join(others, ", "),
			})
		}
	}

	// Агенты: находки правил безопасности и качества, окончание
	// поддержки ОС. Один агент может обслуживать несколько MAC.
	agentIDToMAC := map[string]string{}
	for mac, ref := range agentsByMAC {
		if _, seen := agentIDToMAC[ref.ID]; !seen {
			agentIDToMAC[ref.ID] = mac
		}
	}
	for agentID := range agentIDToMAC {
		signals = append(signals, a.agentSignals(r, agentID, agentsByMAC, snoozed, now)...)
	}

	// Разрыв журнала аудита (NR-023): сигнал уровня карты.
	if !a.auditOK.Load() {
		add(mapSignal{
			DeviceID: "",
			Status:   NodeProblem,
			Kind:     SignalAuditGap,
			Text:     "Журнал аудита повреждён: целостность истории нарушена",
		})
	}

	sortSignals(signals)
	writeJSON(w, http.StatusOK, signalsResponse{
		Signals:  signals,
		Statuses: resolveStatuses(devs, signals),
	})
}

// agentSignals — сигналы одного агента: безопасность (отчёты
// проверок), качество сети (правила по метрикам), окончание
// поддержки ОС. Ошибки отдельных источников пропускаются: сигнал
// лучше молчания, чем падение всего списка.
func (a *API) agentSignals(r *http.Request, agentID string, agentsByMAC map[string]store.AgentRef, snoozed map[string]bool, now time.Time) []mapSignal {
	out := []mapSignal{}
	add := func(s mapSignal) {
		if snoozed[s.DeviceID+"\x00"+s.Kind] {
			return
		}
		out = append(out, s)
	}

	// Безопасность: находки движка проверок по последнему отчёту
	// агента (те же данные, что у экрана «Безопасность»).
	if a.rules != nil {
		sec := security.NewEngine(a.rules)
		res, known := a.agentSecurity(r, sec, agentID, "", now)
		if known {
			for _, f := range res.Findings {
				add(mapSignal{
					DeviceID: agentMACFor(agentID, agentsByMAC),
					Status:   severityToStatus(f.Severity),
					Kind:     SignalSecurity,
					Text:     "Безопасность: " + f.Fact,
				})
			}
		}
		// Качество сети: правила по метрикам (источник «metrics.»).
		if inv, err := a.store.LatestInventory(r.Context(), agentID); err == nil {
			if rep := reportOf(inv); rep != nil {
				for _, f := range a.rules.Evaluate(rep, now) {
					if !strings.HasPrefix(f.Source, "metrics.") {
						continue
					}
					add(mapSignal{
						DeviceID: agentMACFor(agentID, agentsByMAC),
						Status:   severityToStatus(f.Severity),
						Kind:     SignalQuality,
						Text:     "Качество сети: " + f.Fact,
					})
				}
				// Окончание поддержки ОС: Windows 10 после 14.10.2025.
				if caption := osCaption(rep); strings.Contains(strings.ToLower(caption), "windows 10") && now.After(time.Date(2025, 10, 14, 0, 0, 0, 0, time.UTC)) {
					add(mapSignal{
						DeviceID: agentMACFor(agentID, agentsByMAC),
						Status:   NodeProblem,
						Kind:     SignalOS_EOL,
						Text:     "Поддержка Windows 10 закончилась 14.10.2025: обновитесь или замените систему",
					})
				}
			}
		}
	}
	return out
}

// agentMACFor — MAC-устройство агента (первый закреплённый MAC).
func agentMACFor(agentID string, agentsByMAC map[string]store.AgentRef) string {
	for mac, ref := range agentsByMAC {
		if ref.ID == agentID {
			return mac
		}
	}
	return agentID
}

// osCaption — название ОС из инвентаря.
func osCaption(rep *collect.Report) string {
	if rep == nil || rep.OS == nil {
		return ""
	}
	return rep.OS.Caption
}

// severityToStatus — серьёзность правила в статус сигнала.
func severityToStatus(severity string) string {
	if severity == rules.SeverityCritical {
		return NodeProblem
	}
	return NodeAttention
}

// sortSignals — детерминированный порядок: устройство, затем вид.
func sortSignals(list []mapSignal) {
	sort.Slice(list, func(i, j int) bool {
		a, b := list[i], list[j]
		if a.DeviceID != b.DeviceID {
			return a.DeviceID < b.DeviceID
		}
		return a.Kind < b.Kind
	})
}

// resolveStatuses — сводный статус каждого узла: ■ проблема > ▲
// внимание > ○ не в сети > ◇ не проверен > ● в сети. Число открытых
// решений — сигналы с decision.
func resolveStatuses(devs []store.SignalDeviceRow, signals []mapSignal) []nodeStatus {
	// Статусы адресуются индексом: рост среза при append переносит
	// элементы в новый массив, указатели на старый теряют связь.
	byDevice := map[string]int{}
	out := make([]nodeStatus, 0, len(devs))
	for _, d := range devs {
		st := nodeStatus{ID: d.ID, Status: NodeOnline}
		if !d.Verified {
			st.Status = NodeUnverified
		}
		out = append(out, st)
		byDevice[d.ID] = len(out) - 1
	}
	rank := map[string]int{NodeOnline: 0, NodeUnverified: 1, NodeOffline: 2, NodeAttention: 3, NodeProblem: 4}
	for _, s := range signals {
		if s.DeviceID == "" {
			continue
		}
		idx, ok := byDevice[s.DeviceID]
		if !ok {
			continue
		}
		st := &out[idx]
		if s.Decision {
			st.Decisions++
		}
		if rank[s.Status] > rank[st.Status] {
			st.Status = s.Status
		}
	}
	return out
}

// snoozeBody — тело POST /api/signals/snooze.
type snoozeBody struct {
	DeviceID string `json:"device_id"`
	Kind     string `json:"kind"`
	Days     int    `json:"days"`
}

// handleSnoozeSignal — POST /api/signals/snooze: «Игнорировать на N
// дней» — прячет сигнал вида kind у устройства до срока; решение
// фиксируется в журнале аудита.
func (a *API) handleSnoozeSignal(w http.ResponseWriter, r *http.Request) {
	var body snoozeBody
	if err := decodeJSON(r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{err.Error()})
		return
	}
	if body.DeviceID == "" || body.Kind == "" {
		writeJSON(w, http.StatusBadRequest, errorBody{"нужны device_id и kind"})
		return
	}
	if body.Days < 1 || body.Days > 365 {
		writeJSON(w, http.StatusBadRequest, errorBody{"срок — от 1 до 365 дней"})
		return
	}
	now := time.Now()
	if err := a.store.SnoozeSignal(r.Context(), body.DeviceID, body.Kind, now.AddDate(0, 0, body.Days), ActorOwner, now); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
