package agentapi

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ShkodnikAI/NetAtlas/agent/collect"
	"github.com/ShkodnikAI/NetAtlas/pki"
	"github.com/ShkodnikAI/NetAtlas/server/audit"
	"github.com/ShkodnikAI/NetAtlas/server/store"
)

// Границы и константы агентского API.
const (
	// AgentIDPrefix — схема личности агента: CN сертификата.
	AgentIDPrefix = "agent:"
	// MaxEnrollBody — предел тела регистрации (аудитор: 64 КБ).
	MaxEnrollBody = 64 << 10
	// MaxInventoryBody — предел тела инвентаря (аудитор: 2 МБ).
	MaxInventoryBody = 2 << 20
	// MaxMetricsBody — предел тела отчёта метрик (наряд NR-008: 256 КБ).
	MaxMetricsBody = 256 << 10
	// MaxSecurityBody — предел тела отчёта проверок безопасности (NR-010).
	MaxSecurityBody = 256 << 10
	// MaxSecurityResults — предел числа проверок в отчёте.
	MaxSecurityResults = 64
	// MaxCheckIDLen — предел идентификатора проверки.
	MaxCheckIDLen = 64
	// MaxCheckDetailLen — предел текста detail одной проверки.
	MaxCheckDetailLen = 2000
	// MaxCheckDataBytes — предел данных одной проверки (порты и т.п.).
	MaxCheckDataBytes = 64 << 10
	// MaxBlobBytes — предел замера скорости (наряд: не больше 8 МБ).
	MaxBlobBytes = 8 << 20
	// EnrollRatePerMinute — не больше запросов регистрации в минуту с адреса.
	EnrollRatePerMinute = 10
	// DefaultRevocationTTL — кэш списка отзыва не дольше 10 секунд.
	DefaultRevocationTTL = 10 * time.Second
	// DefaultPollInterval — интервал опроса агента по умолчанию.
	DefaultPollInterval = time.Minute
	// MaxHostnameLen — предел имени хоста в регистрации.
	MaxHostnameLen = 255
	// MaxKindLen — предел типа инвентаря.
	MaxKindLen = 64
	// ActorAgentAPI — актор записей аудита агентского API.
	ActorAgentAPI = "agent-api"
)

// API — маршруты агентов. Личность агента берётся из клиентского
// сертификата (CN), тело запроса личность не задаёт никогда.
type API struct {
	st   *store.Store
	ca   *pki.CA
	poll time.Duration

	enroll *rateWindow
	rev    *revocationCache

	agentMux  *http.ServeMux
	enrollMux *http.ServeMux
}

// New собирает агентский API. poll — интервал опроса в ответах
// checkin; ноль заменяется DefaultPollInterval.
func New(st *store.Store, ca *pki.CA, poll time.Duration) (*API, error) {
	if st == nil {
		return nil, errors.New("agentapi: хранилище не задано")
	}
	if ca == nil {
		return nil, errors.New("agentapi: CA не задан")
	}
	if poll <= 0 {
		poll = DefaultPollInterval
	}
	a := &API{
		st:     st,
		ca:     ca,
		poll:   poll,
		enroll: newRateWindow(EnrollRatePerMinute),
		rev:    &revocationCache{ttl: DefaultRevocationTTL},
	}
	agentMux := http.NewServeMux()
	agentMux.HandleFunc("POST /agent/v1/checkin", a.handleCheckin)
	agentMux.HandleFunc("POST /agent/v1/inventory", a.handleInventory)
	agentMux.HandleFunc("POST /agent/v1/metrics", a.handleMetrics)
	agentMux.HandleFunc("POST /agent/v1/security", a.handleSecurity)
	agentMux.HandleFunc("GET /agent/v1/blob", a.handleBlobGet)
	agentMux.HandleFunc("POST /agent/v1/blob", a.handleBlobPost)
	enrollMux := http.NewServeMux()
	enrollMux.HandleFunc("POST /agent/v1/enroll", a.handleEnroll)
	a.agentMux, a.enrollMux = agentMux, enrollMux
	return a, nil
}

// SetRevocationTTL меняет срок кэша списка отзыва (для тестов;
// в работе — DefaultRevocationTTL). Следующая проверка обновит
// список из базы.
func (a *API) SetRevocationTTL(d time.Duration) {
	a.rev.setTTL(d)
}

// MTLSHandler — обработчик для слушателя с обязательным клиентским
// сертификатом: checkin и inventory. Регистрации здесь нет.
func (a *API) MTLSHandler() http.Handler { return a.agentMux }

// EnrollHandler — обработчик слушателя регистрации: единственный
// маршрут без клиентского сертификата (личность ещё не существует —
// только токен).
func (a *API) EnrollHandler() http.Handler { return a.enrollMux }

// MTLSConfig — TLS сервера агентов: TLS 1.3, клиентский сертификат
// обязателен, доверенный корень один — наш CA, отозванные
// отвергаются на handshake.
func (a *API) MTLSConfig(serverCert tls.Certificate) *tls.Config {
	pool := x509.NewCertPool()
	pool.AddCert(a.ca.Cert)
	return &tls.Config{
		Certificates:          []tls.Certificate{serverCert},
		ClientAuth:            tls.RequireAndVerifyClientCert,
		ClientCAs:             pool,
		MinVersion:            tls.VersionTLS13,
		VerifyPeerCertificate: a.verifyPeer,
	}
}

// EnrollConfig — TLS слушателя регистрации: клиентский сертификат
// не требуется и не проверяется (его ещё нет), TLS 1.3.
func (a *API) EnrollConfig(serverCert tls.Certificate) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.NoClientCert,
		MinVersion:   tls.VersionTLS13,
	}
}

// Serve принимает слушатель и TLS-конфиг, блокируется до закрытия
// контекста или ошибки сервера.
func Serve(ctx context.Context, ln net.Listener, tlsCfg *tls.Config, h http.Handler) error {
	srv := &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	if tlsCfg != nil {
		srv.TLSConfig = tlsCfg
	}
	errCh := make(chan error, 1)
	go func() {
		var err error
		if tlsCfg != nil {
			err = srv.ServeTLS(ln, "", "")
		} else {
			err = srv.Serve(ln)
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()
	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		shCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shCtx)
		return nil
	}
}

// verifyPeer — проверка отзыва на handshake: серийный номер
// сертификата в списке отзыва или статус агента revoked.
// Списки читаются из базы с кэшем не дольше TTL.
func (a *API) verifyPeer(_ [][]byte, chains [][]*x509.Certificate) error {
	if len(chains) == 0 || len(chains[0]) == 0 {
		return errors.New("agentapi: нет проверенной цепочки клиентского сертификата")
	}
	leaf := chains[0][0]
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	certs, agents, err := a.rev.load(ctx, a.st)
	if err != nil {
		return fmt.Errorf("agentapi: список отзыва: %w", err)
	}
	if certs[leaf.SerialNumber.String()] {
		return fmt.Errorf("agentapi: сертификат %s отозван", leaf.SerialNumber)
	}
	if id := leaf.Subject.CommonName; agents[id] {
		return fmt.Errorf("agentapi: агент %s отозван", id)
	}
	return nil
}

// revocationCache — кэш списков отзыва (сертификаты и агенты).
type revocationCache struct {
	mu     sync.Mutex
	ttl    time.Duration
	at     time.Time
	certs  map[string]bool
	agents map[string]bool
}

func (c *revocationCache) setTTL(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if d <= 0 {
		return
	}
	c.ttl = d
	c.at = time.Time{} // следующий вызов обновит список
}

func (c *revocationCache) load(ctx context.Context, st *store.Store) (certs, agents map[string]bool, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.certs != nil && time.Since(c.at) < c.ttl {
		return c.certs, c.agents, nil
	}
	serials, err := st.ListRevoked(ctx)
	if err != nil {
		return nil, nil, err
	}
	ids, err := st.ListRevokedAgents(ctx)
	if err != nil {
		return nil, nil, err
	}
	certs = make(map[string]bool, len(serials))
	for _, s := range serials {
		certs[s] = true
	}
	agents = make(map[string]bool, len(ids))
	for _, id := range ids {
		agents[id] = true
	}
	c.certs, c.agents, c.at = certs, agents, time.Now()
	return c.certs, c.agents, nil
}

// rateWindow — скользящее окно «не больше limit принятых запросов в
// минуту с адреса». Отклонённые запросы не считаются: окно считает
// обслуженные попытки.
type rateWindow struct {
	mu    sync.Mutex
	limit int
	seen  map[string][]time.Time
}

func newRateWindow(limit int) *rateWindow {
	return &rateWindow{limit: limit, seen: map[string][]time.Time{}}
}

func (rw *rateWindow) allow(ip string, now time.Time) bool {
	rw.mu.Lock()
	defer rw.mu.Unlock()
	old := rw.seen[ip]
	kept := old[:0]
	for _, t := range old {
		if now.Sub(t) < time.Minute {
			kept = append(kept, t)
		}
	}
	if len(kept) >= rw.limit {
		rw.seen[ip] = kept
		return false
	}
	rw.seen[ip] = append(kept, now)
	return true
}

// peerCN — личность агента из клиентского сертификата.
func peerCN(r *http.Request) (string, error) {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0]) == 0 {
		return "", errors.New("клиентский сертификат отсутствует")
	}
	cn := r.TLS.VerifiedChains[0][0].Subject.CommonName
	if !strings.HasPrefix(cn, AgentIDPrefix) {
		return "", fmt.Errorf("CN %q вне схемы agent:", cn)
	}
	return cn, nil
}

// clientIP — адрес клиента для лимита регистрации.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// errorBody — единый вид ошибки.
type errorBody struct {
	Error string `json:"error"`
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	if v != nil {
		_ = json.NewEncoder(w).Encode(v)
	}
}

// auditDeny — запись об отказе в журнал (без секретов: токены и
// тела не попадают в detail).
func (a *API) auditDeny(ctx context.Context, action, target, reason string) {
	if len(reason) > audit.DetailLimit {
		reason = reason[:audit.DetailLimit]
	}
	_, _ = audit.Append(ctx, a.st.DB(), audit.Entry{
		Actor: ActorAgentAPI, Action: action, Target: target, Result: "deny", Detail: reason,
	})
}

// readBody — чтение тела с пределом; превышение — 413.
func readBody(w http.ResponseWriter, r *http.Request, limit int64) ([]byte, bool) {
	if r.Body == nil {
		r.Body = http.NoBody
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			writeJSON(w, http.StatusRequestEntityTooLarge, errorBody{"тело больше лимита"})
			return nil, false
		}
		writeJSON(w, http.StatusBadRequest, errorBody{"тело не читается"})
		return nil, false
	}
	return raw, true
}

// decodeStrict — строгое чтение JSON: неизвестные поля и лишние
// данные после объекта отклоняются.
func decodeStrict(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("лишние данные после JSON")
	}
	return nil
}

// csrCN — личность из запроса на сертификат: разбор, проверка
// подписи и префикс agent:. Вызывается до расхода токена: подделать
// запрос нельзя, а токен не сгорает.
func csrCN(csrPEM []byte) (string, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return "", errors.New("csr_pem: не PEM CERTIFICATE REQUEST")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("csr_pem: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return "", fmt.Errorf("csr_pem: подпись запроса не сходится: %w", err)
	}
	cn := csr.Subject.CommonName
	if !strings.HasPrefix(cn, AgentIDPrefix) {
		return "", fmt.Errorf("CN %q вне схемы agent:", cn)
	}
	return cn, nil
}

// certSerial — серийный номер выданного сертификата (десятичная
// строка, как в списке отзыва).
func certSerial(certPEM []byte) (string, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return "", errors.New("agentapi: выданный сертификат без PEM")
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("agentapi: выданный сертификат: %w", err)
	}
	return c.SerialNumber.String(), nil
}

// enrollRequest — тело POST /agent/v1/enroll. Личность задаёт CN в
// CSR, поле agent_id в теле не существует.
type enrollRequest struct {
	Token    string   `json:"token"`
	CSRPEM   string   `json:"csr_pem"`
	Hostname string   `json:"hostname"`
	MACs     []string `json:"macs"`
}

// enrollResponse — ответ регистрации: сертификат (цепочка — CA
// сервера, у агента уже есть корень) и интервал опроса.
type enrollResponse struct {
	CertPEM string `json:"cert_pem"`
	AgentID string `json:"agent_id"`
	PollSec int    `json:"poll_interval_s"`
}

// handleEnroll — POST /agent/v1/enroll: токен регистрации + CSR.
// Порядок: лимит частоты → тело → CSR и личность → токен → подпись
// → запись агента и привязка MAC. Всё в аудит.
func (a *API) handleEnroll(w http.ResponseWriter, r *http.Request) {
	if !a.enroll.allow(clientIP(r), time.Now()) {
		// Шторм запросов: в журнал не пишем, чтобы не раздувать его.
		writeJSON(w, http.StatusTooManyRequests, errorBody{"слишком много запросов регистрации"})
		return
	}
	body, ok := readBody(w, r, MaxEnrollBody)
	if !ok {
		return
	}
	var req enrollRequest
	if err := decodeStrict(body, &req); err != nil {
		a.auditDeny(r.Context(), "agent_enroll", "enroll", "тело: "+err.Error())
		writeJSON(w, http.StatusBadRequest, errorBody{"тело запроса: " + err.Error()})
		return
	}
	cn, err := csrCN([]byte(req.CSRPEM))
	if err != nil {
		a.auditDeny(r.Context(), "agent_enroll", "enroll", err.Error())
		writeJSON(w, http.StatusBadRequest, errorBody{err.Error()})
		return
	}
	if len(req.Hostname) > MaxHostnameLen {
		a.auditDeny(r.Context(), "agent_enroll", cn, "hostname длиннее 255")
		writeJSON(w, http.StatusBadRequest, errorBody{"hostname длиннее 255 символов"})
		return
	}
	if err := a.st.ConsumeEnrollToken(r.Context(), req.Token); err != nil {
		switch {
		case errors.Is(err, store.ErrTokenUsed):
			a.auditDeny(r.Context(), "agent_enroll", cn, "токен уже использован")
			writeJSON(w, http.StatusConflict, errorBody{"токен уже использован"})
		case errors.Is(err, store.ErrTokenExpired):
			a.auditDeny(r.Context(), "agent_enroll", cn, "срок токена истёк")
			writeJSON(w, http.StatusUnauthorized, errorBody{"срок токена истёк"})
		default:
			a.auditDeny(r.Context(), "agent_enroll", cn, "токен не принят")
			writeJSON(w, http.StatusUnauthorized, errorBody{"токен не принят"})
		}
		return
	}
	certPEM, err := a.ca.SignAgentCSR([]byte(req.CSRPEM), time.Now())
	if err != nil {
		// Токен уже потрачен на этот CSR: попытка подделать подпись
		// после расхода не даёт второго шанса на тот же токен.
		a.auditDeny(r.Context(), "agent_enroll", cn, "подпись CSR: "+err.Error())
		writeJSON(w, http.StatusBadRequest, errorBody{"CSR не подписан: " + err.Error()})
		return
	}
	serial, err := certSerial(certPEM)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorBody{"серийный номер сертификата"})
		return
	}
	if err := a.st.UpsertAgent(r.Context(), cn, req.Hostname, serial, req.MACs, ActorAgentAPI); err != nil {
		writeJSON(w, http.StatusInternalServerError, errorBody{"запись агента"})
		return
	}
	if err := a.st.LinkAgentMACs(r.Context(), cn, req.MACs); err != nil {
		writeJSON(w, http.StatusInternalServerError, errorBody{"привязка MAC"})
		return
	}
	writeJSON(w, http.StatusCreated, enrollResponse{
		CertPEM: string(certPEM),
		AgentID: cn,
		PollSec: int(a.poll / time.Second),
	})
}

// guardAgent — общий вход checkin и inventory: личность из
// сертификата и свежая проверка статуса мимо кэша handshake.
func (a *API) guardAgent(w http.ResponseWriter, r *http.Request, action string) (string, bool) {
	cn, err := peerCN(r)
	if err != nil {
		a.auditDeny(r.Context(), action, "unknown", err.Error())
		writeJSON(w, http.StatusUnauthorized, errorBody{"клиентский сертификат не опознан"})
		return "", false
	}
	revoked, err := a.st.IsAgentRevoked(r.Context(), cn)
	if errors.Is(err, store.ErrNotFound) {
		a.auditDeny(r.Context(), action, cn, "агент не зарегистрирован")
		writeJSON(w, http.StatusForbidden, errorBody{"агент не зарегистрирован"})
		return "", false
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorBody{"статус агента"})
		return "", false
	}
	if revoked {
		a.auditDeny(r.Context(), action, cn, "агент отозван")
		writeJSON(w, http.StatusForbidden, errorBody{"агент отозван"})
		return "", false
	}
	return cn, true
}

// checkinResponse — ответ heartbeat: заданий пока нет (их добавит
// NR-011), интервал опроса.
type checkinResponse struct {
	Jobs    []any `json:"jobs"`
	PollSec int   `json:"poll_interval_s"`
}

// handleCheckin — POST /agent/v1/checkin: выход агента на связь.
// Успешный heartbeat в журнал не пишется (частота опроса разорвала
// бы цепочку), отказы — пишутся.
func (a *API) handleCheckin(w http.ResponseWriter, r *http.Request) {
	cn, ok := a.guardAgent(w, r, "agent_checkin")
	if !ok {
		return
	}
	if err := a.st.AgentCheckin(r.Context(), cn); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			a.auditDeny(r.Context(), "agent_checkin", cn, "агент не зарегистрирован")
			writeJSON(w, http.StatusForbidden, errorBody{"агент не зарегистрирован"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, errorBody{"checkin"})
		return
	}
	writeJSON(w, http.StatusOK, checkinResponse{Jobs: []any{}, PollSec: int(a.poll / time.Second)})
}

// inventoryRequest — конверт POST /agent/v1/inventory: строгое
// чтение, поле agent_id в теле не существует (личность — сертификат).
type inventoryRequest struct {
	Kind        string          `json:"kind"`
	SchemaVer   int             `json:"schema_ver"`
	CollectedAt time.Time       `json:"collected_at"`
	Payload     json.RawMessage `json:"payload"`
}

// handleInventory — POST /agent/v1/inventory: приём порции данных
// (тело сохраняется как есть), всё в аудит.
func (a *API) handleInventory(w http.ResponseWriter, r *http.Request) {
	cn, ok := a.guardAgent(w, r, "agent_inventory")
	if !ok {
		return
	}
	body, ok := readBody(w, r, MaxInventoryBody)
	if !ok {
		return
	}
	var inv inventoryRequest
	if err := decodeStrict(body, &inv); err != nil {
		a.auditDeny(r.Context(), "agent_inventory", cn, "тело: "+err.Error())
		writeJSON(w, http.StatusBadRequest, errorBody{"тело запроса: " + err.Error()})
		return
	}
	if inv.Kind == "" || len(inv.Kind) > MaxKindLen {
		a.auditDeny(r.Context(), "agent_inventory", cn, "kind пуст или длиннее 64")
		writeJSON(w, http.StatusBadRequest, errorBody{"kind: непустой, до 64 символов"})
		return
	}
	if inv.SchemaVer < 1 {
		a.auditDeny(r.Context(), "agent_inventory", cn, "schema_ver меньше 1")
		writeJSON(w, http.StatusBadRequest, errorBody{"schema_ver: целое не меньше 1"})
		return
	}
	trimmed := bytes.TrimSpace(inv.Payload)
	if len(trimmed) == 0 || trimmed[0] != '{' || !json.Valid(trimmed) {
		a.auditDeny(r.Context(), "agent_inventory", cn, "payload не JSON-объект")
		writeJSON(w, http.StatusBadRequest, errorBody{"payload: JSON-объект"})
		return
	}
	if err := a.st.SaveInventory(r.Context(), cn, inv.Kind, inv.SchemaVer, inv.CollectedAt, body); err != nil {
		writeJSON(w, http.StatusInternalServerError, errorBody{"сохранение инвентаря"})
		return
	}
	// Точки истории дисков для прогноза заполнения (NR-009): ошибка
	// записи не отменяет приём инвентаря, но видна в журнале сервера.
	if err := saveDiskPoints(a.st, cn, body); err != nil {
		log.Printf("agentapi: история дисков %s: %v", cn, err)
	}
	writeJSON(w, http.StatusAccepted, map[string]bool{"ok": true})
}

// saveDiskPoints — дневные точки занятого места из отчёта инвентаря:
// конверт → payload → тома отчёта версии 1.
func saveDiskPoints(st *store.Store, agentID string, body []byte) error {
	var env inventoryRequest
	if err := json.Unmarshal(body, &env); err != nil {
		return nil // не конверт — истории нет
	}
	var rep collect.Report
	if err := json.Unmarshal(env.Payload, &rep); err != nil {
		return nil // не отчёт v1 — истории нет
	}
	if rep.Disks == nil {
		return nil
	}
	now := time.Now()
	points := make([]store.DiskPoint, 0, len(rep.Disks.Volumes))
	for _, v := range rep.Disks.Volumes {
		if v.DriveLetter == "" || v.Size == "" || v.SizeRemaining == "" {
			continue
		}
		var size, free int64
		if _, err := fmt.Sscanf(strings.TrimSpace(v.Size), "%d", &size); err != nil {
			continue
		}
		if _, err := fmt.Sscanf(strings.TrimSpace(v.SizeRemaining), "%d", &free); err != nil {
			continue
		}
		if size <= 0 {
			continue
		}
		points = append(points, store.DiskPoint{Drive: v.DriveLetter, Used: size - free, Capacity: size})
	}
	if len(points) == 0 {
		return nil
	}
	return st.SaveDiskHistory(context.Background(), agentID, points, now)
}

// metricsRequest — конверт метрик (схема версии 1).
type metricsRequest struct {
	Kind        string    `json:"kind"` // "metrics"
	SchemaVer   int       `json:"schema_ver"`
	CollectedAt time.Time `json:"collected_at"`
	Samples     []struct {
		Target string  `json:"target"`
		Metric string  `json:"metric"`
		Value  float64 `json:"value"`
	} `json:"samples"`
}

// handleMetrics — POST /agent/v1/metrics: приём порции замеров
// (тело ≤256 КБ, строгий JSON), точки — в хранилище метрик.
func (a *API) handleMetrics(w http.ResponseWriter, r *http.Request) {
	cn, ok := a.guardAgent(w, r, "agent_metrics")
	if !ok {
		return
	}
	body, ok := readBody(w, r, MaxMetricsBody)
	if !ok {
		return
	}
	var req metricsRequest
	if err := decodeStrict(body, &req); err != nil {
		a.auditDeny(r.Context(), "agent_metrics", cn, "тело: "+err.Error())
		writeJSON(w, http.StatusBadRequest, errorBody{"тело запроса: " + err.Error()})
		return
	}
	if req.Kind != "metrics" || req.SchemaVer < 1 {
		a.auditDeny(r.Context(), "agent_metrics", cn, "kind/schema_ver")
		writeJSON(w, http.StatusBadRequest, errorBody{"kind=metrics и schema_ver ≥ 1"})
		return
	}
	if len(req.Samples) > 512 {
		a.auditDeny(r.Context(), "agent_metrics", cn, "слишком много точек")
		writeJSON(w, http.StatusBadRequest, errorBody{"samples: не больше 512"})
		return
	}
	at := req.CollectedAt
	if at.IsZero() {
		at = time.Now()
	}
	samples := make([]store.MetricSample, 0, len(req.Samples))
	for _, sm := range req.Samples {
		samples = append(samples, store.MetricSample{
			AgentID: cn, Target: sm.Target, Kind: sm.Metric, Value: sm.Value, At: at,
		})
	}
	if err := a.st.SaveMetricsRaw(r.Context(), samples); err != nil {
		writeJSON(w, http.StatusInternalServerError, errorBody{"сохранение метрик"})
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]bool{"ok": true})
}

// securityRequest — конверт отчёта проверок безопасности
// (схема версии 1). Проверка может нести данные (например, список
// слушающих портов) — они сохраняются как есть в пределах лимита.
type securityRequest struct {
	Kind        string    `json:"kind"` // "security"
	SchemaVer   int       `json:"schema_ver"`
	CollectedAt time.Time `json:"collected_at"`
	Results     []struct {
		ID     string          `json:"id"`
		Status string          `json:"status"`
		Detail string          `json:"detail,omitempty"`
		Data   json.RawMessage `json:"data,omitempty"`
	} `json:"results"`
}

// handleSecurity — POST /agent/v1/security: приём отчёта проверок
// безопасности агента (тело ≤256 КБ, строгий JSON), всё в аудит.
func (a *API) handleSecurity(w http.ResponseWriter, r *http.Request) {
	cn, ok := a.guardAgent(w, r, "agent_security")
	if !ok {
		return
	}
	body, ok := readBody(w, r, MaxSecurityBody)
	if !ok {
		return
	}
	var req securityRequest
	if err := decodeStrict(body, &req); err != nil {
		a.auditDeny(r.Context(), "agent_security", cn, "тело: "+err.Error())
		writeJSON(w, http.StatusBadRequest, errorBody{"тело запроса: " + err.Error()})
		return
	}
	if req.Kind != "security" || req.SchemaVer < 1 {
		a.auditDeny(r.Context(), "agent_security", cn, "kind/schema_ver")
		writeJSON(w, http.StatusBadRequest, errorBody{"kind=security и schema_ver ≥ 1"})
		return
	}
	if len(req.Results) > MaxSecurityResults {
		a.auditDeny(r.Context(), "agent_security", cn, "слишком много проверок")
		writeJSON(w, http.StatusBadRequest, errorBody{"results: не больше 64"})
		return
	}
	seen := map[string]bool{}
	for _, res := range req.Results {
		switch {
		case res.ID == "" || len(res.ID) > MaxCheckIDLen:
			a.auditDeny(r.Context(), "agent_security", cn, "id проверки пуст или длиннее 64")
			writeJSON(w, http.StatusBadRequest, errorBody{"id проверки: непустой, до 64 символов"})
			return
		case seen[res.ID]:
			a.auditDeny(r.Context(), "agent_security", cn, "повтор id проверки")
			writeJSON(w, http.StatusBadRequest, errorBody{"results: повтор id " + res.ID})
			return
		case res.Status != "pass" && res.Status != "fail" && res.Status != "unknown":
			a.auditDeny(r.Context(), "agent_security", cn, "недопустимый статус проверки")
			writeJSON(w, http.StatusBadRequest, errorBody{"status: pass | fail | unknown"})
			return
		case len(res.Detail) > MaxCheckDetailLen:
			a.auditDeny(r.Context(), "agent_security", cn, "detail длиннее 2000")
			writeJSON(w, http.StatusBadRequest, errorBody{"detail: до 2000 символов"})
			return
		case len(res.Data) > MaxCheckDataBytes:
			a.auditDeny(r.Context(), "agent_security", cn, "data больше 64 КБ")
			writeJSON(w, http.StatusBadRequest, errorBody{"data: до 65536 байт"})
			return
		case len(res.Data) > 0 && (!json.Valid(res.Data) || strings.TrimSpace(string(res.Data))[0] != '{'):
			a.auditDeny(r.Context(), "agent_security", cn, "data не JSON-объект")
			writeJSON(w, http.StatusBadRequest, errorBody{"data: JSON-объект"})
			return
		}
		seen[res.ID] = true
	}
	at := req.CollectedAt
	if at.IsZero() {
		at = time.Now()
	}
	if err := a.st.SaveSecurity(r.Context(), cn, req.SchemaVer, at, body); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			a.auditDeny(r.Context(), "agent_security", cn, "агент не зарегистрирован")
			writeJSON(w, http.StatusForbidden, errorBody{"агент не зарегистрирован"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, errorBody{"сохранение отчёта безопасности"})
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]bool{"ok": true})
}

// handleBlobGet — GET /agent/v1/blob?bytes=N: отдаёт N нулевых байт
// (не больше 8 МБ) для замера скорости загрузки агентом.
func (a *API) handleBlobGet(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.guardAgent(w, r, "agent_blob"); !ok {
		return
	}
	n, err := strconv.Atoi(r.URL.Query().Get("bytes"))
	if err != nil || n < 1 || n > MaxBlobBytes {
		writeJSON(w, http.StatusBadRequest, errorBody{"bytes: 1..8388608"})
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.Itoa(n))
	w.WriteHeader(http.StatusOK)
	// Нулевой буфер пишется порциями: память не зависит от N.
	chunk := make([]byte, 64<<10)
	for n > 0 {
		k := n
		if k > len(chunk) {
			k = len(chunk)
		}
		if _, err := w.Write(chunk[:k]); err != nil {
			return
		}
		n -= k
	}
}

// handleBlobPost — POST /agent/v1/blob: приём до 8 МБ (замер
// скорости выгрузки), тело не сохраняется.
func (a *API) handleBlobPost(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.guardAgent(w, r, "agent_blob"); !ok {
		return
	}
	if _, ok := readBody(w, r, MaxBlobBytes); !ok {
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]bool{"ok": true})
}
