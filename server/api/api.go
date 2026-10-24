// Package api — HTTP API карты сети поверх хранилища: только
// стандартная библиотека net/http (маршруты Go 1.22). Без токена ни
// один маршрут не отвечает данными; всё, что идёт в сеть (только
// ping), идёт только внутри Scope и через Limiter.
package api

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ShkodnikAI/NetAtlas/internal/model"
	"github.com/ShkodnikAI/NetAtlas/scanner"
	"github.com/ShkodnikAI/NetAtlas/server/audit"
	"github.com/ShkodnikAI/NetAtlas/server/store"
)

// MinTokenLen — минимальная длина токена авторизации.
const MinTokenLen = 24

// MaxBodyBytes — предел тела запроса.
const MaxBodyBytes = 1 << 20

// ActorOwner — актор изменяющих операций: владелец за интерфейсом.
const ActorOwner = "owner"

// Store — интерфейс хранилища, необходимый API (подменяется в тестах).
type Store interface {
	Topology(ctx context.Context) (store.Graph, error)
	Device(ctx context.Context, id string) (store.DeviceInfo, error)
	AddManualDevice(ctx context.Context, kind, label, actor string) (string, error)
	UpdateDevice(ctx context.Context, id string, upd store.Update, actor string) error
	DeleteManualDevice(ctx context.Context, id, actor string) error
	AddManualLink(ctx context.Context, a, aPort, b, bPort, actor string) (string, error)
	DeleteManualLink(ctx context.Context, id, actor string) error
	RecordVerification(ctx context.Context, id, actor string, alive bool, detail string) error
	ListDevices(ctx context.Context) ([]store.DeviceInfo, error)
	ListDevicesByClass(ctx context.Context, class model.Class) ([]store.DeviceInfo, error)
	AppendAudit(ctx context.Context, actor, action, target, detail string) error
	SaveScan(ctx context.Context, scan store.ScanResult, actor string) error
	ListAlerts(ctx context.Context) ([]store.Alert, error)
	AckAlert(ctx context.Context, id int64, actor string) error
	IssueEnrollToken(ctx context.Context, actor string) (string, error)
	ListAgents(ctx context.Context) ([]store.Agent, error)
	RevokeAgent(ctx context.Context, id, actor string) error
	DB() *sql.DB
}

// Prober — проверка живости адреса (подменяется в тестах).
type Prober interface {
	Ping(ctx context.Context, dst netip.Addr) (time.Duration, bool, error)
}

// API — обработчики и зависимости.
type API struct {
	store   Store
	token   string
	scope   *scanner.Scope
	limiter *scanner.Limiter
	prober  Prober
	mux     *http.ServeMux

	// auditOK — состояние цепочки журнала аудита на старте сервера
	// (NR-023): проверка в cmd/netatlas-server до старта HTTP;
	// /api/config отдаёт её как audit_ok.
	auditOK atomic.Bool

	// Скан (NR-005): конфигурация и подменяемые зависимости;
	// ConfigureScan подключает, до вызова — 503.
	scanMu      sync.Mutex
	scanCfg     *ServerScanConfig
	scanDeps    *ScanDeps
	scanRunning bool
	nextScanID  int64
	scans       map[int64]*ScanState
}

// New собирает API. Токен короче 24 символов — ошибка (сервер не
// стартует). scope, limiter и prober обязательны для verify.
func New(st Store, token string, scope *scanner.Scope, limiter *scanner.Limiter, prober Prober) (*API, error) {
	if len(token) < MinTokenLen {
		return nil, fmt.Errorf("api: токен короче %d символов", MinTokenLen)
	}
	if st == nil {
		return nil, fmt.Errorf("api: хранилище не задано")
	}
	a := &API{store: st, token: token, scope: scope, limiter: limiter, prober: prober}
	a.auditOK.Store(true) // цепочка целая, пока проверка старта не скажет иное
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/topology", a.handleTopology)
	mux.HandleFunc("GET /api/devices/{id}", a.handleDevice)
	mux.HandleFunc("POST /api/devices", a.handleAddDevice)
	mux.HandleFunc("PATCH /api/devices/{id}", a.handleUpdateDevice)
	mux.HandleFunc("DELETE /api/devices/{id}", a.handleDeleteDevice)
	mux.HandleFunc("POST /api/links", a.handleAddLink)
	mux.HandleFunc("DELETE /api/links/{id}", a.handleDeleteLink)
	mux.HandleFunc("POST /api/devices/{id}/verify", a.handleVerify)
	mux.HandleFunc("GET /api/audit", a.handleAudit)
	mux.HandleFunc("GET /api/audit/verify", a.handleAuditVerify)
	mux.HandleFunc("GET /api/devices", a.handleDevicesList)
	mux.HandleFunc("POST /api/scan", a.handleScanStart)
	mux.HandleFunc("GET /api/scan/{id}", a.handleScanStatus)
	mux.HandleFunc("GET /api/alerts", a.handleAlerts)
	mux.HandleFunc("POST /api/alerts/{id}/ack", a.handleAlertAck)
	mux.HandleFunc("GET /api/config", a.handleConfig)
	mux.HandleFunc("POST /api/agents/enrollment", a.handleAgentEnrollment)
	mux.HandleFunc("GET /api/agents", a.handleAgentsList)
	mux.HandleFunc("POST /api/agents/{id}/revoke", a.handleAgentRevoke)
	a.mux = mux
	return a, nil
}

// Handler — конвейер: заголовки безопасности → лимит тела →
// авторизация → маршруты.
func (a *API) Handler() http.Handler {
	return a.withSecurity(a.withBodyLimit(a.withAuth(a.mux)))
}

// SetAuditOK фиксирует состояние цепочки журнала аудита на старте
// сервера: разрыв (ошибка Verify) даёт false. Вызывается до старта
// HTTP; дальше флаг только читается /api/config.
func (a *API) SetAuditOK(ok bool) {
	a.auditOK.Store(ok)
}

// withSecurity — заголовки на каждый ответ; CORS не выдаётся.
func (a *API) withSecurity(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// withBodyLimit — тело запроса больше MaxBodyBytes отклоняется.
func (a *API) withBodyLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, MaxBodyBytes)
		}
		next.ServeHTTP(w, r)
	})
}

// withAuth — сравнение Bearer-токена за постоянное время; без токена
// ответ 401 без данных.
func (a *API) withAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		const prefix = "Bearer "
		ok := false
		if got, found := strings.CutPrefix(r.Header.Get("Authorization"), prefix); found {
			ok = subtle.ConstantTimeCompare([]byte(got), []byte(a.token)) == 1
		}
		if !ok {
			w.Header().Set("WWW-Authenticate", `Bearer realm="netatlas"`)
			writeJSON(w, http.StatusUnauthorized, errorBody{"требуется авторизация"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

// errorBody — единый вид ошибки.
type errorBody struct {
	Error string `json:"error"`
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	if v != nil {
		_ = json.NewEncoder(w).Encode(v)
	}
}

// decodeJSON — строгое чтение тела: неизвестные поля отклоняются.
func decodeJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("api: тело запроса: %w", err)
	}
	if dec.More() {
		return fmt.Errorf("api: тело запроса: лишние данные после JSON")
	}
	return nil
}

// fail — маппинг ошибок хранилища в коды ответов.
func fail(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeJSON(w, http.StatusNotFound, errorBody{"не найдено"})
	case errors.Is(err, store.ErrNotManual):
		writeJSON(w, http.StatusConflict, errorBody{"элемент не ручной: удаление запрещено"})
	case errors.Is(err, store.ErrBackupExists):
		writeJSON(w, http.StatusConflict, errorBody{"файл уже существует"})
	case errors.Is(err, store.ErrAgentRevoked):
		writeJSON(w, http.StatusConflict, errorBody{"агент уже отозван"})
	default:
		writeJSON(w, http.StatusInternalServerError, errorBody{"внутренняя ошибка"})
	}
}

// handleTopology — GET /api/topology: узлы и связи с manual/verified.
func (a *API) handleTopology(w http.ResponseWriter, r *http.Request) {
	g, err := a.store.Topology(r.Context())
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, g)
}

// handleDevice — GET /api/devices/{id}: карточка устройства.
func (a *API) handleDevice(w http.ResponseWriter, r *http.Request) {
	info, err := a.store.Device(r.Context(), r.PathValue("id"))
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, info)
}

// addDeviceBody — тело POST /api/devices.
type addDeviceBody struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
}

// handleAddDevice — POST /api/devices: ручной элемент.
func (a *API) handleAddDevice(w http.ResponseWriter, r *http.Request) {
	var body addDeviceBody
	if err := decodeJSON(r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{err.Error()})
		return
	}
	id, err := a.store.AddManualDevice(r.Context(), body.Kind, body.Name, ActorOwner)
	if err != nil {
		if isBadRequest(err) {
			writeJSON(w, http.StatusBadRequest, errorBody{err.Error()})
			return
		}
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"id": id})
}

// isBadRequest — ошибки входных значений (тип, имя, класс): 400, а не 500.
func isBadRequest(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "недопустимый тип") ||
		strings.Contains(msg, "недопустимый класс") ||
		strings.Contains(msg, "длиннее")
}

// updateDeviceBody — тело PATCH /api/devices/{id}.
type updateDeviceBody struct {
	Name     *string      `json:"name,omitempty"`
	Class    *model.Class `json:"class,omitempty"`
	Verified *bool        `json:"verified,omitempty"`
}

// handleUpdateDevice — PATCH /api/devices/{id}: имя, класс, verified.
func (a *API) handleUpdateDevice(w http.ResponseWriter, r *http.Request) {
	var body updateDeviceBody
	if err := decodeJSON(r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{err.Error()})
		return
	}
	upd := store.Update{Name: body.Name, Verified: body.Verified}
	if body.Class != nil {
		class, err := model.ParseClass(string(*body.Class))
		if err != nil {
			writeJSON(w, http.StatusBadRequest, errorBody{err.Error()})
			return
		}
		upd.Class = &class
	}
	id := r.PathValue("id")
	if err := a.store.UpdateDevice(r.Context(), id, upd, ActorOwner); err != nil {
		fail(w, err)
		return
	}
	info, err := a.store.Device(r.Context(), id)
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, info)
}

// handleDeleteDevice — DELETE /api/devices/{id}: только ручные.
func (a *API) handleDeleteDevice(w http.ResponseWriter, r *http.Request) {
	if err := a.store.DeleteManualDevice(r.Context(), r.PathValue("id"), ActorOwner); err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// addLinkBody — тело POST /api/links.
type addLinkBody struct {
	A     string `json:"a"`
	APort string `json:"a_port"`
	B     string `json:"b"`
	BPort string `json:"b_port"`
}

// handleAddLink — POST /api/links: ручная связь.
func (a *API) handleAddLink(w http.ResponseWriter, r *http.Request) {
	var body addLinkBody
	if err := decodeJSON(r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{err.Error()})
		return
	}
	id, err := a.store.AddManualLink(r.Context(), body.A, body.APort, body.B, body.BPort, ActorOwner)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			fail(w, err)
			return
		}
		if isBadRequest(err) {
			writeJSON(w, http.StatusBadRequest, errorBody{err.Error()})
			return
		}
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"id": id})
}

// handleDeleteLink — DELETE /api/links/{id}: только ручные.
func (a *API) handleDeleteLink(w http.ResponseWriter, r *http.Request) {
	if err := a.store.DeleteManualLink(r.Context(), r.PathValue("id"), ActorOwner); err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// pingResult — итог проверки одного адреса.
type pingResult struct {
	IP    string  `json:"ip"`
	Alive bool    `json:"alive"`
	RTTms float64 `json:"rtt_ms,omitempty"`
}

// verifyReport — ответ POST /api/devices/{id}/verify.
type verifyReport struct {
	ID       string       `json:"id"`
	Verified bool         `json:"verified"`
	Results  []pingResult `json:"results"`
}

// handleVerify — настоящая проверка живости: ping каждого IP внутри
// Scope через Limiter. Устройство без IP или со всеми адресами вне
// Scope даёт 400, сеть не трогается.
func (a *API) handleVerify(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	info, err := a.store.Device(r.Context(), id)
	if err != nil {
		fail(w, err)
		return
	}
	if len(info.IPs) == 0 {
		writeJSON(w, http.StatusBadRequest, errorBody{"у устройства нет адресов: проверять нечего"})
		return
	}
	if a.scope == nil || a.limiter == nil || a.prober == nil {
		writeJSON(w, http.StatusServiceUnavailable, errorBody{"проверка недоступна: нет границ сети или пробера"})
		return
	}
	targets := make([]netip.Addr, 0, len(info.IPs))
	for _, ip := range info.IPs {
		if a.scope.Contains(ip) {
			targets = append(targets, ip)
		}
	}
	if len(targets) == 0 {
		writeJSON(w, http.StatusBadRequest, errorBody{"адреса устройства вне подсетей проверки: сеть не трогается"})
		return
	}

	results := make([]pingResult, 0, len(targets))
	alive := 0
	for _, ip := range targets {
		res := pingResult{IP: ip.String()}
		release, err := a.limiter.Acquire(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, errorBody{"лимитер: " + err.Error()})
			return
		}
		rtt, ok, err := a.prober.Ping(r.Context(), ip)
		release()
		if err == nil {
			res.Alive = ok
			if ok {
				alive++
				res.RTTms = float64(rtt) / float64(time.Millisecond)
			}
		}
		results = append(results, res)
	}
	verified := alive > 0
	detail, err := json.Marshal(struct {
		Alive   int          `json:"alive"`
		Total   int          `json:"total"`
		Results []pingResult `json:"results"`
	}{Alive: alive, Total: len(results), Results: results})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorBody{"сводка проверки"})
		return
	}
	if err := a.store.RecordVerification(r.Context(), id, ActorOwner, verified, string(detail)); err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, verifyReport{ID: id, Verified: verified, Results: results})
}

// handleAudit — GET /api/audit?limit=: последние записи журнала.
func (a *API) handleAudit(w http.ResponseWriter, r *http.Request) {
	limit := 0
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 0 {
			writeJSON(w, http.StatusBadRequest, errorBody{"limit: целое неотрицательное"})
			return
		}
		limit = n
	}
	entries, err := audit.List(r.Context(), a.store.DB(), limit, 0)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorBody{"журнал аудита"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": entries})
}

// auditVerifyResponse — ответ GET /api/audit/verify: целостность
// цепочки журнала (NR-023). Разрыв — не ошибка сервера, а факт,
// поэтому ответ 200 в обоих случаях.
type auditVerifyResponse struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// handleAuditVerify — GET /api/audit/verify: проверка цепочки хэшей
// от начала до конца.
func (a *API) handleAuditVerify(w http.ResponseWriter, r *http.Request) {
	if err := audit.Verify(r.Context(), a.store.DB()); err != nil {
		writeJSON(w, http.StatusOK, auditVerifyResponse{OK: false, Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, auditVerifyResponse{OK: true})
}

// handleAgentEnrollment — POST /api/agents/enrollment: выдача
// одноразового токена регистрации. Токен показывается один раз: в
// базе и аудите только хэш (NR-007).
func (a *API) handleAgentEnrollment(w http.ResponseWriter, r *http.Request) {
	token, err := a.store.IssueEnrollToken(r.Context(), ActorOwner)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorBody{"выдача токена регистрации"})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"token":        token,
		"expires_in_s": int(store.EnrollTokenTTL / time.Second),
		"enroll_route": "/agent/v1/enroll",
	})
}

// handleAgentsList — GET /api/agents: карточки зарегистрированных
// агентов (состояния, серийники, MAC-списки).
func (a *API) handleAgentsList(w http.ResponseWriter, r *http.Request) {
	agents, err := a.store.ListAgents(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorBody{"список агентов"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"agents": agents})
}

// handleAgentRevoke — POST /api/agents/{id}/revoke: отзыв агента.
// Следующий handshake отозванного отвергается (кэш списка отзыва
// агентского API не дольше 10 секунд).
func (a *API) handleAgentRevoke(w http.ResponseWriter, r *http.Request) {
	if err := a.store.RevokeAgent(r.Context(), r.PathValue("id"), ActorOwner); err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
