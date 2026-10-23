package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/ShkodnikAI/NetAtlas/internal/model"
	"github.com/ShkodnikAI/NetAtlas/scanner"
	"github.com/ShkodnikAI/NetAtlas/scanner/ping"
	"github.com/ShkodnikAI/NetAtlas/scanner/pipeline"
	"github.com/ShkodnikAI/NetAtlas/scanner/snmp"
	"github.com/ShkodnikAI/NetAtlas/server/store"
)

// ScanRequest — тело POST /api/scan.
type ScanRequest struct {
	Subnets     []string `json:"subnets"`
	Ping        bool     `json:"ping"`
	Names       bool     `json:"names"`
	SNMPTargets []string `json:"snmp_targets"`
	Confirm     bool     `json:"confirm"`
}

// ServerScanConfig — подсети сервера и доступность SNMP (учётные
// данные только из окружения сервера; в API и ответы не попадают).
type ServerScanConfig struct {
	Subnets   []string
	SNMPAuth  snmp.Auth
	SNMPReady bool
}

// ScanDeps — подменяемые источники серверного сканирования.
type ScanDeps struct {
	ReadARP     pipeline.ARPSource
	NewProber   func() (ping.Prober, func(), error)
	NewNameConn func() (net.PacketConn, error)
	NewWalker   pipeline.WalkerFactory
}

// ScanState — состояние одного сканирования для GET /api/scan/{id}.
type ScanState struct {
	ID      int64             `json:"id"`
	Status  string            `json:"status"` // running | done | failed
	Stages  []string          `json:"stages"`
	Counts  pipeline.Counters `json:"counts"`
	Error   string            `json:"error,omitempty"`
	Subnets []string          `json:"subnets"`
}

const scanTimeout = 30 * time.Minute

// ConfigureScan подключает мастер сканирования: без вызова POST
// /api/scan отвечает 503.
func (a *API) ConfigureScan(cfg ServerScanConfig, deps ScanDeps) {
	a.scanMu.Lock()
	defer a.scanMu.Unlock()
	a.scanCfg = &cfg
	a.scanDeps = &deps
	a.scans = map[int64]*ScanState{}
}

// scanRequestData — изменяющаяся часть API-сканирования.
type scanRuntime struct {
	mu      sync.Mutex
	running bool
	nextID  int64
}

// handleScanStart — POST /api/scan: подтверждение, границы, запуск
// в фоне. Одновременно идёт только одно сканирование.
func (a *API) handleScanStart(w http.ResponseWriter, r *http.Request) {
	a.scanMu.Lock()
	cfg, deps := a.scanCfg, a.scanDeps
	running := a.scanRunning
	a.scanMu.Unlock()

	if cfg == nil || deps == nil {
		writeJSON(w, http.StatusServiceUnavailable, errorBody{"сканирование не настроено на сервере"})
		return
	}
	var body ScanRequest
	if err := decodeJSON(r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{err.Error()})
		return
	}
	if !body.Confirm {
		writeJSON(w, http.StatusBadRequest, errorBody{"без явного подтверждения (confirm=true) сканирование не запускается"})
		return
	}
	if len(body.Subnets) == 0 {
		writeJSON(w, http.StatusBadRequest, errorBody{"список подсетей пуст"})
		return
	}
	// Подсети только из конфигурации сервера: расширить границы нельзя.
	for _, raw := range body.Subnets {
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, errorBody{fmt.Sprintf("подсеть %q не CIDR", raw)})
			return
		}
		if !a.scope.ContainsPrefix(p) {
			writeJSON(w, http.StatusBadRequest, errorBody{fmt.Sprintf("подсеть %q вне подсетей сервера: расширение границ запрещено", raw)})
			return
		}
	}
	scanScope, err := scanner.NewScope(body.Subnets, true)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{err.Error()})
		return
	}
	var targets []netip.Addr
	if len(body.SNMPTargets) > 0 {
		targets, err = parseScanTargets(body.SNMPTargets)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, errorBody{err.Error()})
			return
		}
		if err := snmp.CheckTargets(scanScope, targets); err != nil {
			writeJSON(w, http.StatusBadRequest, errorBody{err.Error()})
			return
		}
		if !cfg.SNMPReady {
			writeJSON(w, http.StatusBadRequest, errorBody{"SNMP-учётные данные не настроены на сервере (переменные окружения NETATLAS_SNMP_*)"})
			return
		}
	}

	a.scanMu.Lock()
	if running || a.scanRunning {
		a.scanMu.Unlock()
		writeJSON(w, http.StatusConflict, errorBody{"сканирование уже идёт: одновременный запуск запрещён"})
		return
	}
	a.nextScanID++
	id := a.nextScanID
	a.scanRunning = true
	st := &ScanState{ID: id, Status: "running", Stages: []string{}, Subnets: body.Subnets}
	a.scans[id] = st
	a.scanMu.Unlock()

	// Действие пишется в аудит (актор owner): ошибка аудита делает
	// операцию неуспешной.
	detail, _ := json.Marshal(map[string]any{
		"subnets": body.Subnets, "ping": body.Ping,
		"names": body.Names, "snmp_targets": len(targets),
	})
	if err := a.store.AppendAudit(r.Context(), ActorOwner, "start_scan", "scan", string(detail)); err != nil {
		a.scanMu.Lock()
		a.scanRunning = false
		delete(a.scans, id)
		a.scanMu.Unlock()
		writeJSON(w, http.StatusInternalServerError, errorBody{"журнал аудита недоступен: сканирование не запущено"})
		return
	}

	go a.runScan(st, body, targets, *cfg, *deps, scanScope)
	writeJSON(w, http.StatusAccepted, map[string]int64{"id": id})
}

// runScan — фоновое выполнение: конвейер, затем сохранение через
// store.SaveScan (аудит пишет сам SaveScan). Признак «идёт
// сканирование» снимается только здесь — по факту завершения.
func (a *API) runScan(st *ScanState, body ScanRequest, targets []netip.Addr, cfg ServerScanConfig, deps ScanDeps, scanScope *scanner.Scope) {
	defer func() {
		a.scanMu.Lock()
		a.scanRunning = false
		a.scanMu.Unlock()
	}()
	ctx, cancel := context.WithTimeout(context.Background(), scanTimeout)
	defer cancel()

	// Гости и «известные без агента» не опрашиваются по именам и SNMP.
	skip := map[string]bool{}
	if devs, err := a.store.ListDevices(ctx); err == nil {
		for _, d := range devs {
			if d.Class == model.ClassGuest || d.Class == model.ClassKnownNoAgent {
				skip[d.ID] = true
			}
		}
	}

	addStage := func(name string) {
		a.scanMu.Lock()
		st.Stages = append(st.Stages, name)
		a.scanMu.Unlock()
	}
	// Стадия ping/names отмечается по включённости метода.
	pcfg := pipeline.Config{
		Scope:        scanScope,
		Limiter:      a.limiter,
		Ping:         body.Ping,
		Names:        body.Names,
		SNMPTargets:  targets,
		SNMPAuth:     cfg.SNMPAuth,
		SkipDeepMACs: skip,
		OnStage:      addStage,
	}
	res, err := pipeline.Run(ctx, pcfg, pipeline.Deps{
		ReadARP:     deps.ReadARP,
		NewProber:   deps.NewProber,
		NewNameConn: deps.NewNameConn,
		NewWalker:   deps.NewWalker,
	})
	if err != nil {
		a.scanMu.Lock()
		st.Status = "failed"
		st.Error = err.Error()
		a.scanMu.Unlock()
		return
	}

	// Сохранение результата: SaveScan пишет аудит в той же транзакции.
	now := time.Now()
	err = a.store.SaveScan(ctx, store.ScanResult{
		Started:  now.Add(-time.Minute),
		Finished: now,
		Subnets:  body.Subnets,
		Devices:  res.Devices,
		Topology: res.Topology,
	}, ActorOwner)
	a.scanMu.Lock()
	defer a.scanMu.Unlock()
	if err != nil {
		st.Status = "failed"
		st.Error = err.Error()
		return
	}
	st.Status = "done"
	st.Counts = res.Counts
}

// handleScanStatus — GET /api/scan/{id}.
func (a *API) handleScanStatus(w http.ResponseWriter, r *http.Request) {
	raw := r.PathValue("id")
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{"идентификатор сканирования: целое число"})
		return
	}
	a.scanMu.Lock()
	st, ok := a.scans[id]
	// Снимок под блокировкой: сериализуем копию — фоновый скан
	// продолжает писать оригинал.
	var snap ScanState
	if ok {
		snap = *st
		snap.Stages = append([]string(nil), st.Stages...)
	}
	a.scanMu.Unlock()
	if !ok {
		writeJSON(w, http.StatusNotFound, errorBody{"сканирование не найдено"})
		return
	}
	writeJSON(w, http.StatusOK, &snap)
}

// parseScanTargets — цели SNMP из тела запроса.
func parseScanTargets(raw []string) ([]netip.Addr, error) {
	out := make([]netip.Addr, 0, len(raw))
	for _, p := range raw {
		a, err := netip.ParseAddr(p)
		if err != nil || !a.Is4() {
			return nil, fmt.Errorf("цель %q не IPv4-адрес", p)
		}
		out = append(out, a)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("список целей пуст")
	}
	return out, nil
}

// handleDevicesList — GET /api/devices?class=: список для экрана
// «Найденные устройства».
func (a *API) handleDevicesList(w http.ResponseWriter, r *http.Request) {
	class := r.URL.Query().Get("class")
	var (
		devs []store.DeviceInfo
		err  error
	)
	if class == "" {
		devs, err = a.store.ListDevices(r.Context())
	} else {
		devs, err = a.store.ListDevicesByClass(r.Context(), model.Class(class))
	}
	if err != nil {
		if isBadRequest(err) {
			writeJSON(w, http.StatusBadRequest, errorBody{err.Error()})
			return
		}
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"devices": devs})
}

// handleAlerts — GET /api/alerts: открытые оповещения.
func (a *API) handleAlerts(w http.ResponseWriter, r *http.Request) {
	alerts, err := a.store.ListAlerts(r.Context())
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"alerts": alerts})
}

// handleAlertAck — POST /api/alerts/{id}/ack: разбор владельцем.
func (a *API) handleAlertAck(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{"идентификатор оповещения: целое число"})
		return
	}
	if err := a.store.AckAlert(r.Context(), id, ActorOwner); err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// configResponse — конфигурация для мастера сканирования (без
// секретов): границы сервера и доступность SNMP.
type configResponse struct {
	Subnets []string `json:"subnets"`
	SNMP    bool     `json:"snmp"`
}

// handleConfig — GET /api/config.
func (a *API) handleConfig(w http.ResponseWriter, _ *http.Request) {
	cfg := a.scanCfg
	resp := configResponse{Subnets: []string{}}
	if cfg != nil {
		resp.Subnets = cfg.Subnets
		resp.SNMP = cfg.SNMPReady
	}
	writeJSON(w, http.StatusOK, resp)
}
