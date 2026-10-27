package api

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/ShkodnikAI/NetAtlas/internal/model"
	"github.com/ShkodnikAI/NetAtlas/scanner"
	"github.com/ShkodnikAI/NetAtlas/server/store"
)

// fakeStore — подставное хранилище без сети.
type fakeStore struct {
	devices   map[string]store.DeviceInfo
	nextID    int
	notManual map[string]bool // ошибки удаления
	recorded  []struct {
		id    string
		actor string
		alive bool
	}
	deletedDevice string
	deletedLink   string

	agents        []store.Agent
	positions     map[string][2]float64
	positionOrder []string
	// Сигналы внимания (NR-033): подставляемые данные.
	signalDevices   []store.SignalDeviceRow
	openAlerts      []store.OpenAlert
	agentsByMAC     map[string]store.AgentRef
	snoozes         map[string]time.Time
	lastSnooze      [3]string // device, kind, actor
	activityAccount map[string]string
	auditEntries    []store.HistoryEntry
	// graph — заглушка для Topology, если задана (тесты NR-032).
	graph         *store.Graph
	kindUpdates   []store.Update
	metrics       map[string][]store.MetricAgg
	inventory     map[string]store.InventoryRow
	security      map[string]string // agent → тело отчёта (NR-010)
	agentExists   map[string]bool
	revokedAgents map[string]bool
	enrollTokens  int
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		security:        map[string]string{},
		devices:         map[string]store.DeviceInfo{},
		notManual:       map[string]bool{},
		agentExists:     map[string]bool{},
		metrics:         map[string][]store.MetricAgg{},
		inventory:       map[string]store.InventoryRow{},
		revokedAgents:   map[string]bool{},
		agentsByMAC:     map[string]store.AgentRef{},
		snoozes:         map[string]time.Time{},
		activityAccount: map[string]string{},
	}
}

func (f *fakeStore) addDev(id string, ips ...netip.Addr) {
	d := store.DeviceInfo{Manual: true}
	d.ID = id
	d.MAC = id
	d.Class = model.ClassUnknown
	d.IPs = ips
	d.Names = []model.Name{}
	d.Observations = []model.Observation{}
	f.devices[id] = d
}

func (f *fakeStore) Topology(ctx context.Context) (store.Graph, error) {
	if f.graph != nil {
		return *f.graph, nil
	}
	g := store.Graph{Nodes: []store.NodeInfo{}, Links: []store.LinkInfo{}}
	for id, d := range f.devices {
		g.Nodes = append(g.Nodes, store.NodeInfo{Node: model.Node{ID: id, Kind: model.NodeKindDevice, Label: id},
			Manual: d.Manual, Verified: d.Verified})
	}
	return g, nil
}

func (f *fakeStore) Device(ctx context.Context, id string) (store.DeviceInfo, error) {
	d, ok := f.devices[id]
	if !ok {
		return store.DeviceInfo{}, store.ErrNotFound
	}
	return d, nil
}

func (f *fakeStore) AddManualDevice(ctx context.Context, kind, label, actor string) (string, error) {
	if kind != model.NodeKindDevice && kind != model.NodeKindSwitch {
		return "", fmt.Errorf("store: недопустимый тип элемента %q", kind)
	}
	f.nextID++
	id := fmt.Sprintf("manual:%08d", f.nextID)
	f.addDev(id)
	return id, nil
}

func (f *fakeStore) UpdateDevice(ctx context.Context, id string, upd store.Update, actor string) error {
	f.kindUpdates = append(f.kindUpdates, upd)
	d, ok := f.devices[id]
	if !ok {
		return store.ErrNotFound
	}
	if upd.Class != nil && !upd.Class.Valid() {
		return fmt.Errorf("store: недопустимый класс %q", string(*upd.Class))
	}
	if upd.Class != nil {
		d.Class = *upd.Class
	}
	if upd.Verified != nil {
		d.Verified = *upd.Verified
	}
	f.devices[id] = d
	return nil
}

func (f *fakeStore) DeleteManualDevice(ctx context.Context, id, actor string) error {
	if _, ok := f.devices[id]; !ok {
		return store.ErrNotFound
	}
	if f.notManual[id] {
		return store.ErrNotManual
	}
	delete(f.devices, id)
	f.deletedDevice = id
	return nil
}

func (f *fakeStore) AddManualLink(ctx context.Context, a, aPort, b, bPort, actor string) (string, error) {
	if a == b {
		return "", fmt.Errorf("store: связь требует двух разных узлов")
	}
	for _, end := range []string{a, b} {
		if _, ok := f.devices[end]; !ok {
			return "", fmt.Errorf("store: узел %s: %w", end, store.ErrNotFound)
		}
	}
	f.nextID++
	return fmt.Sprintf("manual:%08d", f.nextID), nil
}

func (f *fakeStore) DeleteManualLink(ctx context.Context, id, actor string) error {
	if id != "manual:1" {
		return store.ErrNotFound
	}
	f.deletedLink = id
	return nil
}

func (f *fakeStore) Positions(ctx context.Context) ([]store.NodePosition, error) {
	out := []store.NodePosition{}
	for _, id := range f.positionOrder {
		p := f.positions[id]
		out = append(out, store.NodePosition{ID: id, X: p[0], Y: p[1]})
	}
	return out, nil
}

func (f *fakeStore) SavePosition(ctx context.Context, id string, x, y float64, actor string) error {
	if _, ok := f.devices[id]; !ok {
		return store.ErrNotFound
	}
	if f.positions == nil {
		f.positions = map[string][2]float64{}
	}
	if _, seen := f.positions[id]; !seen {
		f.positionOrder = append(f.positionOrder, id)
	}
	f.positions[id] = [2]float64{x, y}
	return nil
}

func (f *fakeStore) SavePositions(ctx context.Context, pos []store.NodePosition, actor string) (int, error) {
	saved := 0
	for _, p := range pos {
		if _, ok := f.devices[p.ID]; !ok {
			continue
		}
		if err := f.SavePosition(ctx, p.ID, p.X, p.Y, actor); err != nil {
			continue
		}
		saved++
	}
	return saved, nil
}

func (f *fakeStore) ClearPositions(ctx context.Context, actor string) error {
	f.positions = map[string][2]float64{}
	f.positionOrder = nil
	return nil
}

func (f *fakeStore) RecordVerification(ctx context.Context, id, actor string, alive bool, detail string) error {
	f.recorded = append(f.recorded, struct {
		id    string
		actor string
		alive bool
	}{id, actor, alive})
	return nil
}

func (f *fakeStore) setClass(id, class string) {
	d := f.devices[id]
	d.Class = model.Class(class)
	f.devices[id] = d
}

func (f *fakeStore) ListDevices(ctx context.Context) ([]store.DeviceInfo, error) {
	out := []store.DeviceInfo{}
	for _, d := range f.devices {
		out = append(out, d)
	}
	return out, nil
}

func (f *fakeStore) ListDevicesByClass(ctx context.Context, class model.Class) ([]store.DeviceInfo, error) {
	if !class.Valid() {
		return nil, fmt.Errorf("store: недопустимый класс устройства %q", string(class))
	}
	all, err := f.ListDevices(ctx)
	if err != nil {
		return nil, err
	}
	out := []store.DeviceInfo{}
	for _, d := range all {
		if d.Class == class {
			out = append(out, d)
		}
	}
	return out, nil
}

func (f *fakeStore) AppendAudit(ctx context.Context, actor, action, target, detail string) error {
	return nil
}

func (f *fakeStore) SaveScan(ctx context.Context, scan store.ScanResult, actor string) error {
	return nil
}

func (f *fakeStore) ListAlerts(ctx context.Context) ([]store.Alert, error) {
	return []store.Alert{}, nil
}

func (f *fakeStore) AckAlert(ctx context.Context, id int64, actor string) error {
	if id != 1 {
		return store.ErrNotFound
	}
	return nil
}

func (f *fakeStore) DB() *sql.DB { return nil }

// fakeProber — подставной пробер со счётчиком вызовов.
type fakeProber struct {
	calls int
	alive map[string]bool
}

func (p *fakeProber) Ping(ctx context.Context, dst netip.Addr) (time.Duration, bool, error) {
	p.calls++
	if p.alive == nil {
		return 0, false, nil
	}
	return 5 * time.Millisecond, p.alive[dst.String()], nil
}

const token = "0123456789abcdef01234567"

func testAPI(t *testing.T, st Store, prober Prober) http.Handler {
	t.Helper()
	scope, err := scanner.NewScope([]string{"10.0.0.0/24"}, false)
	if err != nil {
		t.Fatalf("scope: %v", err)
	}
	limiter, err := scanner.NewLimiter(4, 1000, nil)
	if err != nil {
		t.Fatalf("limiter: %v", err)
	}
	a, err := New(st, token, scope, limiter, prober)
	if err != nil {
		t.Fatalf("api: %v", err)
	}
	return a.Handler()
}

func do(r http.Handler, method, path, body, authHeader string) *httptest.ResponseRecorder {
	var reader *bytes.Reader
	if body == "" {
		reader = bytes.NewReader(nil)
	} else {
		reader = bytes.NewReader([]byte(body))
	}
	req := httptest.NewRequest(method, path, reader)
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

const bearer = "Bearer " + token

// Без токена и с неверным токеном данные не отвечаются (401).
func TestUnauthorized(t *testing.T) {
	h := testAPI(t, newFakeStore(), &fakeProber{})
	for _, auth := range []string{"", "Bearer нет", bearer + "x", "Basic " + token} {
		rec := do(h, "GET", "/api/topology", "", auth)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("auth %q: код %d, хочу 401", auth, rec.Code)
		}
		if strings.Contains(rec.Body.String(), `"nodes"`) {
			t.Fatalf("auth %q: данные утекли: %s", auth, rec.Body.String())
		}
	}
}

// Токен короче 24 символов: API не создаётся.
func TestShortTokenRejected(t *testing.T) {
	if _, err := New(newFakeStore(), "короткий", nil, nil, nil); err == nil {
		t.Fatalf("короткий токен принят")
	}
}

// Удаление найденного устройства — 409, чужого — 404.
func TestDeleteDeviceCodes(t *testing.T) {
	fs := newFakeStore()
	fs.addDev("00:00:00:00:00:0b")
	fs.notManual["00:00:00:00:00:0b"] = true
	h := testAPI(t, fs, &fakeProber{})
	if rec := do(h, "DELETE", "/api/devices/00:00:00:00:00:0b", "", bearer); rec.Code != http.StatusConflict {
		t.Fatalf("удаление найденного: код %d, хочу 409: %s", rec.Code, rec.Body.String())
	}
	if rec := do(h, "DELETE", "/api/devices/00:00:00:00:00:99", "", bearer); rec.Code != http.StatusNotFound {
		t.Fatalf("чужое устройство: код %d, хочу 404", rec.Code)
	}
	// Ручное удаляется.
	id, err := fs.AddManualDevice(context.Background(), model.NodeKindDevice, "x", "owner")
	if err != nil {
		t.Fatalf("ручной элемент: %v", err)
	}
	if rec := do(h, "DELETE", "/api/devices/"+id, "", bearer); rec.Code != http.StatusOK {
		t.Fatalf("удаление ручного: код %d: %s", rec.Code, rec.Body.String())
	}
	if fs.deletedDevice != id {
		t.Fatalf("удалён %q, хочу %q", fs.deletedDevice, id)
	}
}

// Verify без адресов — 400, сеть не трогается.
func TestVerifyNoIPs(t *testing.T) {
	fs := newFakeStore()
	fs.addDev("00:00:00:00:00:0b")
	p := &fakeProber{}
	h := testAPI(t, fs, p)
	rec := do(h, "POST", "/api/devices/00:00:00:00:00:0b/verify", "", bearer)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("код %d, хочу 400: %s", rec.Code, rec.Body.String())
	}
	if p.calls != 0 {
		t.Fatalf("пробер вызван %d раз, хочу 0", p.calls)
	}
}

// Verify с адресом вне Scope — 400, пробер не вызывается.
func TestVerifyOutOfScope(t *testing.T) {
	fs := newFakeStore()
	ip := netip.MustParseAddr("10.9.9.9") // вне 10.0.0.0/24
	fs.addDev("00:00:00:00:00:0b", ip)
	p := &fakeProber{}
	h := testAPI(t, fs, p)
	rec := do(h, "POST", "/api/devices/00:00:00:00:00:0b/verify", "", bearer)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("код %d, хочу 400: %s", rec.Code, rec.Body.String())
	}
	if p.calls != 0 {
		t.Fatalf("пробер вызван %d раз, хочу 0 (сеть не трогается)", p.calls)
	}
}

// Verify с подставным пробером: живое устройство получает verified и
// запись проверки; мёртвое — нет.
func TestVerifyWithFakeProber(t *testing.T) {
	fs := newFakeStore()
	ip := netip.MustParseAddr("10.0.0.11")
	fs.addDev("00:00:00:00:00:0b", ip)
	p := &fakeProber{alive: map[string]bool{"10.0.0.11": true}}
	h := testAPI(t, fs, p)

	rec := do(h, "POST", "/api/devices/00:00:00:00:00:0b/verify", "", bearer)
	if rec.Code != http.StatusOK {
		t.Fatalf("код %d: %s", rec.Code, rec.Body.String())
	}
	var report verifyReport
	if err := json.Unmarshal(rec.Body.Bytes(), &report); err != nil {
		t.Fatalf("ответ: %v", err)
	}
	if !report.Verified || len(report.Results) != 1 || !report.Results[0].Alive {
		t.Fatalf("отчёт = %+v, хочу verified с живым адресом", report)
	}
	if p.calls != 1 {
		t.Fatalf("вызовов пробера = %d, хочу 1", p.calls)
	}
	if len(fs.recorded) != 1 || fs.recorded[0].id != "00:00:00:00:00:0b" ||
		fs.recorded[0].actor != ActorOwner || !fs.recorded[0].alive {
		t.Fatalf("запись проверки = %+v", fs.recorded)
	}

	// Мёртвый адрес: verified=false, запись с alive=false.
	p2 := &fakeProber{}
	h2 := testAPI(t, fs, p2)
	rec = do(h2, "POST", "/api/devices/00:00:00:00:00:0b/verify", "", bearer)
	if rec.Code != http.StatusOK {
		t.Fatalf("код %d: %s", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &report); err != nil {
		t.Fatalf("ответ: %v", err)
	}
	if report.Verified {
		t.Fatalf("мёртвое устройство помечено проверенным: %+v", report)
	}
	if len(fs.recorded) != 2 || fs.recorded[1].alive {
		t.Fatalf("вторая запись = %+v, хочу alive=false", fs.recorded[1])
	}
}

// Неизвестное поле в теле отклоняется.
func TestUnknownFieldRejected(t *testing.T) {
	fs := newFakeStore()
	h := testAPI(t, fs, &fakeProber{})
	rec := do(h, "POST", "/api/devices", `{"kind":"device","name":"x","evil":1}`, bearer)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("код %d, хочу 400: %s", rec.Code, rec.Body.String())
	}
}

// Тело больше 1 МБ отклоняется.
func TestBodyTooLarge(t *testing.T) {
	fs := newFakeStore()
	h := testAPI(t, fs, &fakeProber{})
	big := `{"kind":"device","name":"` + strings.Repeat("а", 1<<20) + `"}`
	rec := do(h, "POST", "/api/devices", big, bearer)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("код %d, хочу 400: %s", rec.Code, rec.Body.String())
	}
}

// PATCH с недопустимым классом — 400; с допустимым — обновление.
func TestPatchClass(t *testing.T) {
	fs := newFakeStore()
	fs.addDev("00:00:00:00:00:0b")
	h := testAPI(t, fs, &fakeProber{})
	rec := do(h, "PATCH", "/api/devices/00:00:00:00:00:0b", `{"class":"самозванец"}`, bearer)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("плохой класс: код %d, хочу 400", rec.Code)
	}
	rec = do(h, "PATCH", "/api/devices/00:00:00:00:00:0b", `{"class":"guest"}`, bearer)
	if rec.Code != http.StatusOK {
		t.Fatalf("класс guest: код %d: %s", rec.Code, rec.Body.String())
	}
	if fs.devices["00:00:00:00:00:0b"].Class != model.ClassGuest {
		t.Fatalf("класс не записан: %+v", fs.devices["00:00:00:00:00:0b"])
	}
}

// Добавление ручного элемента и связи: 201 с идентификатором.
func TestAddManual(t *testing.T) {
	fs := newFakeStore()
	fs.addDev("00:00:00:00:00:0b")
	h := testAPI(t, fs, &fakeProber{})
	rec := do(h, "POST", "/api/devices", `{"kind":"device","name":"новый"}`, bearer)
	if rec.Code != http.StatusCreated {
		t.Fatalf("код %d: %s", rec.Code, rec.Body.String())
	}
	var out struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || !strings.HasPrefix(out.ID, "manual:") {
		t.Fatalf("ответ = %s (err %v)", rec.Body.String(), err)
	}
	rec = do(h, "POST", "/api/links",
		`{"a":"`+out.ID+`","a_port":"","b":"00:00:00:00:00:0b","b_port":"Gi0/1"}`, bearer)
	if rec.Code != http.StatusCreated {
		t.Fatalf("связь: код %d: %s", rec.Code, rec.Body.String())
	}
	// Связь к несуществующему узлу — 404.
	rec = do(h, "POST", "/api/links",
		`{"a":"`+out.ID+`","a_port":"","b":"00:00:00:00:00:ff","b_port":""}`, bearer)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("связь с чужим узлом: код %d, хочу 404", rec.Code)
	}
}

// Топология отвечает данными только с токеном; флаги manual присутствуют.
func TestTopologyRoute(t *testing.T) {
	fs := newFakeStore()
	fs.addDev("00:00:00:00:00:0b")
	h := testAPI(t, fs, &fakeProber{})
	rec := do(h, "GET", "/api/topology", "", bearer)
	if rec.Code != http.StatusOK {
		t.Fatalf("код %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"manual"`) {
		t.Fatalf("в ответе нет признака manual: %s", rec.Body.String())
	}
}

// Интеграция с настоящим хранилищем: проверка пишет аудит, выставляет
// verified и наблюдение «verify» — одной транзакцией store.
func TestVerifyWritesAuditWithRealStore(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/netatlas.db")
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	defer st.Close()
	now := time.Now()
	d, err := model.NewDevice("00:00:00:00:00:0b")
	if err != nil {
		t.Fatalf("устройство: %v", err)
	}
	d.IPs = append(d.IPs, netip.MustParseAddr("10.0.0.11"))
	scan := store.ScanResult{Started: now, Finished: now, Subnets: []string{"10.0.0.0/24"},
		Devices: []model.Device{d}, Topology: model.NewTopology()}
	if err := st.SaveScan(context.Background(), scan, "owner"); err != nil {
		t.Fatalf("скан: %v", err)
	}

	fs := &realStoreWrap{st}
	p := &fakeProber{alive: map[string]bool{"10.0.0.11": true}}
	h := testAPI(t, fs, p)
	rec := do(h, "POST", "/api/devices/00:00:00:00:00:0b/verify", "", bearer)
	if rec.Code != http.StatusOK {
		t.Fatalf("код %d: %s", rec.Code, rec.Body.String())
	}

	info, err := st.Device(context.Background(), "00:00:00:00:00:0b")
	if err != nil {
		t.Fatalf("карточка: %v", err)
	}
	if !info.Verified {
		t.Fatalf("verified не выставлен")
	}
	hasVerify := false
	for _, o := range info.Observations {
		if o.Source == "verify" {
			hasVerify = true
		}
	}
	if !hasVerify {
		t.Fatalf("наблюдения = %+v, хочу verify", info.Observations)
	}
}

// realStoreWrap — *store.Store подходит под интерфейс API.
type realStoreWrap struct{ *store.Store }

// IssueEnrollToken — фейковая выдача токена регистрации.
func (f *fakeStore) IssueEnrollToken(ctx context.Context, actor string) (string, error) {
	f.enrollTokens++
	return "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", nil
}

// ListAgents — фейковый список агентов.
func (f *fakeStore) ListAgents(ctx context.Context) ([]store.Agent, error) {
	return f.agents, nil
}

// LatestInventory — фейковая последняя порция инвентаря.
func (f *fakeStore) LatestInventory(ctx context.Context, agentID string) (store.InventoryRow, error) {
	row, ok := f.inventory[agentID]
	if !ok {
		return store.InventoryRow{}, store.ErrNotFound
	}
	return row, nil
}

// LatestMetrics — фейковые метрики (пустые).
func (f *fakeStore) LatestMetrics(ctx context.Context, agentID string) ([]store.MetricAgg, error) {
	return f.metrics[agentID], nil
}

// SeriesMetrics — фейковый ряд метрик (пустой).
func (f *fakeStore) SeriesMetrics(ctx context.Context, agentID, target, kind string, from, to time.Time, hourly bool) ([]store.MetricAgg, error) {
	return nil, nil
}

// LatestSecurity — фейковый отчёт проверок безопасности (NR-010).
func (f *fakeStore) LatestSecurity(ctx context.Context, agentID string) (store.SecurityRow, error) {
	if raw, ok := f.security[agentID]; ok {
		return store.SecurityRow{SchemaVer: 1, CollectedAt: time.Now(), JSON: raw}, nil
	}
	return store.SecurityRow{}, store.ErrNotFound
}

// AgentByID — фейковая карточка агента.
func (f *fakeStore) AgentByID(ctx context.Context, id string) (store.Agent, error) {
	if f.agentExists[id] {
		for _, a := range f.agents {
			if a.ID == id {
				return a, nil
			}
		}
	}
	return store.Agent{}, store.ErrNotFound
}

// DiskHistory — фейковая история дисков (пустая).
func (f *fakeStore) DiskHistory(ctx context.Context, agentID, drive string, days int) ([]store.DiskPoint, error) {
	return nil, nil
}

// RevokeAgent — фейковый отзыв: состояния как в настоящем store.
func (f *fakeStore) RevokeAgent(ctx context.Context, id, actor string) error {
	if !f.agentExists[id] {
		return store.ErrNotFound
	}
	if f.revokedAgents[id] {
		return store.ErrAgentRevoked
	}
	f.revokedAgents[id] = true
	return nil
}

// addAgent — фикстура агента для тестов маршрутов владельца.
func (f *fakeStore) addAgent(id string) {
	f.agentExists[id] = true
	f.agents = append(f.agents, store.Agent{ID: id, Hostname: "pc", Status: "active", MACList: []string{}})
}

// --- Конвейер скриптов (NR-011): фейковые заглушки. Скриптовые
// маршруты тестируются на настоящем store (api_scripts_test.go);
// вызов фейка — ошибка теста, а не тихое поведение.
func (f *fakeStore) CreateScript(ctx context.Context, in store.CreateScriptInput, actor string) (int64, int64, error) {
	panic("скриптовые тесты используют настоящий store")
}

func (f *fakeStore) CreateVersion(ctx context.Context, scriptID int64, in store.CreateScriptInput, actor string) (int64, error) {
	panic("скриптовые тесты используют настоящий store")
}

func (f *fakeStore) ListScripts(ctx context.Context) ([]store.ScriptRow, []store.VersionRow, error) {
	panic("скриптовые тесты используют настоящий store")
}

func (f *fakeStore) ScriptCard(ctx context.Context, id int64) (store.ScriptRow, []store.VersionRow, map[int64][]store.CheckRow, map[int64]store.SignatureRow, error) {
	panic("скриптовые тесты используют настоящий store")
}

func (f *fakeStore) VersionContent(ctx context.Context, scriptID, versionID int64) (store.VersionFull, error) {
	panic("скриптовые тесты используют настоящий store")
}

func (f *fakeStore) AdvanceStatus(ctx context.Context, scriptID, versionID int64, to, comment, actor string) (store.VersionRow, error) {
	panic("скриптовые тесты используют настоящий store")
}

func (f *fakeStore) RecordCheck(ctx context.Context, scriptID, versionID int64, in store.CheckRow, pass bool) (store.VersionRow, error) {
	panic("скриптовые тесты используют настоящий store")
}

func (f *fakeStore) VersionBySHA256(ctx context.Context, sha string) (int64, int64, error) {
	panic("скриптовые тесты используют настоящий store")
}

func (f *fakeStore) SignVersion(ctx context.Context, scriptID, versionID int64, sha, signature string, expires time.Time, actor string) (store.VersionRow, error) {
	panic("скриптовые тесты используют настоящий store")
}

func (f *fakeStore) StageCounts(ctx context.Context) (map[string]int, error) {
	panic("скриптовые тесты используют настоящий store")
}

func (f *fakeStore) CreateJob(ctx context.Context, in store.CreateJobInput, actor string) (int64, error) {
	panic("скриптовые тесты используют настоящий store")
}

func (f *fakeStore) ListJobs(ctx context.Context, versionID int64) ([]store.JobRow, error) {
	panic("скриптовые тесты используют настоящий store")
}

func (f *fakeStore) JobByID(ctx context.Context, jobID int64) (store.JobRow, error) {
	panic("скриптовые тесты используют настоящий store")
}

func (f *fakeStore) StopJob(ctx context.Context, jobID int64, reason, actor string) error {
	panic("скриптовые тесты используют настоящий store")
}

func (f *fakeStore) SaveSecurity(ctx context.Context, agentID string, schemaVer int, collectedAt time.Time, raw []byte) error {
	panic("скриптовые тесты используют настоящий store")
}

// --- Активность (NR-012): фейковые заглушки; настоящие тесты на
// store (api_activity_test.go использует настоящий store).
func (f *fakeStore) EnableActivity(ctx context.Context, agentID, phrase, actor string) error {
	panic("активность тестируется на настоящем store")
}

func (f *fakeStore) DisableActivity(ctx context.Context, agentID, actor string) error {
	panic("активность тестируется на настоящем store")
}

func (f *fakeStore) ActivityEnabled(ctx context.Context, agentID string) (bool, error) {
	return false, nil
}

func (f *fakeStore) ListActivityEnabled(ctx context.Context) ([]store.ActivityStatus, error) {
	panic("активность тестируется на настоящем store")
}

func (f *fakeStore) SaveActivity(ctx context.Context, row store.ActivityRow) error {
	panic("активность тестируется на настоящем store")
}

func (f *fakeStore) ActivityAggregates(ctx context.Context, from, to time.Time, agentID, account string) (store.ActivitySummary, error) {
	panic("активность тестируется на настоящем store")
}

func (f *fakeStore) PurgeOldActivity(ctx context.Context, now time.Time) (int64, error) {
	return 0, nil
}

func (f *fakeStore) DeleteActivityFor(ctx context.Context, agentID, actor string) (int64, error) {
	panic("активность тестируется на настоящем store")
}

// --- Отчёты для ИИ (NR-013): настоящие тесты на store.
func (f *fakeStore) CreateAIReport(ctx context.Context, topic, cleanedText string, mapping []store.MappingRow) (int64, error) {
	panic("отчёты тестируются на настоящем store")
}

func (f *fakeStore) AIReportByID(ctx context.Context, id int64) (store.AIReport, error) {
	panic("отчёты тестируются на настоящем store")
}

func (f *fakeStore) ListAIReports(ctx context.Context) ([]store.AIReport, error) {
	panic("отчёты тестируются на настоящем store")
}

func (f *fakeStore) SaveAIAnswer(ctx context.Context, id int64, answer string) error {
	panic("отчёты тестируются на настоящем store")
}

func (f *fakeStore) AIMapping(ctx context.Context, id int64) ([]store.MappingRow, error) {
	panic("отчёты тестируются на настоящем store")
}

// --- Сигналы внимания (NR-033 п.4): подставные данные. ---

func (f *fakeStore) SignalDevices(ctx context.Context) ([]store.SignalDeviceRow, error) {
	return append([]store.SignalDeviceRow(nil), f.signalDevices...), nil
}

func (f *fakeStore) OpenAlerts(ctx context.Context) ([]store.OpenAlert, error) {
	return append([]store.OpenAlert(nil), f.openAlerts...), nil
}

func (f *fakeStore) OpenAlertsByDevice(ctx context.Context, deviceID string) ([]store.OpenAlert, error) {
	out := []store.OpenAlert{}
	for _, a := range f.openAlerts {
		if a.DeviceID == deviceID {
			out = append(out, a)
		}
	}
	return out, nil
}

func (f *fakeStore) AgentsByMAC(ctx context.Context) (map[string]store.AgentRef, error) {
	out := map[string]store.AgentRef{}
	for mac, ref := range f.agentsByMAC {
		out[mac] = ref
	}
	return out, nil
}

func (f *fakeStore) ActiveSnoozes(ctx context.Context, now time.Time) (map[string]bool, error) {
	out := map[string]bool{}
	for key, until := range f.snoozes {
		if until.After(now) {
			out[key] = true
		}
	}
	return out, nil
}

func (f *fakeStore) SnoozeSignal(ctx context.Context, deviceID, kind string, until time.Time, actor string, now time.Time) error {
	f.lastSnooze = [3]string{deviceID, kind, actor}
	f.snoozes[deviceID+"\x00"+kind] = until
	return nil
}

func (f *fakeStore) LastActivityAccount(ctx context.Context, agentID string) (string, error) {
	return f.activityAccount[agentID], nil
}

func (f *fakeStore) AuditForTarget(ctx context.Context, target string, limit int) ([]store.HistoryEntry, error) {
	return append([]store.HistoryEntry(nil), f.auditEntries...), nil
}
