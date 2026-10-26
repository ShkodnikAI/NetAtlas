// Тесты NR-033 в API: сигналы внимания (новые устройства, долгое
// молчание, один IP у нескольких MAC, отложенные сигналы), сводные
// статусы узлов и расширенная карточка устройства.

package api

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/ShkodnikAI/NetAtlas/scanner"
	"github.com/ShkodnikAI/NetAtlas/server/store"
)

// mustScope — подсеть для тестового API.
func mustScope(t *testing.T) *scanner.Scope {
	t.Helper()
	scope, err := scanner.NewScope([]string{"10.0.0.0/24"}, false)
	if err != nil {
		t.Fatalf("scope: %v", err)
	}
	return scope
}

// nr033Signals — разбор ответа GET /api/signals.
type nr033Signals struct {
	Signals  []mapSignal  `json:"signals"`
	Statuses []nodeStatus `json:"statuses"`
}

func nr033Get(t *testing.T, fs *fakeStore) nr033Signals {
	t.Helper()
	a, err := New(fs, token, mustScope(t), mustLimiter(t), &fakeProber{})
	if err != nil {
		t.Fatalf("api: %v", err)
	}
	h := a.Handler()
	rec := do(h, "GET", "/api/signals", "", bearer)
	if rec.Code != 200 {
		t.Fatalf("GET /api/signals: код %d: %s", rec.Code, rec.Body.String())
	}
	var out nr033Signals
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("разбор ответа: %v", err)
	}
	return out
}

// TestNR033UnknownNewSignal — открытое оповещение о новом неизвестном
// устройстве даёт сигнал «внимание» с решением и статус узла ▲.
func TestNR033UnknownNewSignal(t *testing.T) {
	fs := newFakeStore()
	fs.signalDevices = []store.SignalDeviceRow{
		{ID: "aa:bb:cc:dd:ee:01", Class: "unknown", IPs: []string{"192.168.100.10"}},
	}
	fs.openAlerts = []store.OpenAlert{{ID: 1, DeviceID: "aa:bb:cc:dd:ee:01", Created: time.Now()}}
	out := nr033Get(t, fs)
	if len(out.Signals) != 1 {
		t.Fatalf("сигналов %d, хочу 1: %+v", len(out.Signals), out.Signals)
	}
	s := out.Signals[0]
	if s.Kind != SignalUnknownNew || s.Status != NodeAttention || !s.Decision {
		t.Fatalf("сигнал %+v, хочу unknown_new/attention/decision", s)
	}
	if s.DeviceID != "aa:bb:cc:dd:ee:01" {
		t.Fatalf("device_id %q", s.DeviceID)
	}
	if len(out.Statuses) != 1 || out.Statuses[0].Status != NodeAttention || out.Statuses[0].Decisions != 1 {
		t.Fatalf("статусы %+v, хочу attention c одним решением", out.Statuses)
	}
}

// TestNR033NoResponseSignal — устройство, молчащее больше порога,
// даёт сигнал «не в сети»; свежее устройство — нет.
func TestNR033NoResponseSignal(t *testing.T) {
	fs := newFakeStore()
	stale := time.Now().Add(-noResponseThreshold - time.Hour)
	fresh := time.Now()
	fs.signalDevices = []store.SignalDeviceRow{
		{ID: "aa:00:00:00:00:01", Class: "managed", Verified: true, LastSeen: stale},
		{ID: "aa:00:00:00:00:02", Class: "managed", Verified: true, LastSeen: fresh},
	}
	out := nr033Get(t, fs)
	if len(out.Signals) != 1 {
		t.Fatalf("сигналов %d, хочу 1 (только устаревшее): %+v", len(out.Signals), out.Signals)
	}
	s := out.Signals[0]
	if s.Kind != SignalNoResponse || s.Status != NodeOffline || s.Decision {
		t.Fatalf("сигнал %+v, хочу no_response/offline без решения", s)
	}
	if s.DeviceID != "aa:00:00:00:00:01" {
		t.Fatalf("device_id %q", s.DeviceID)
	}
	// Статус устаревшего — offline (verified, поэтому не unverified).
	for _, st := range out.Statuses {
		if st.ID == "aa:00:00:00:00:01" && st.Status != NodeOffline {
			t.Fatalf("статус устаревшего %q, хочу offline", st.Status)
		}
		if st.ID == "aa:00:00:00:00:02" && st.Status != NodeOnline {
			t.Fatalf("статус свежего %q, хочу online", st.Status)
		}
	}
}

// TestNR033IPConflictSignal — один IP у двух MAC: сигнал внимания
// обоим устройствам.
func TestNR033IPConflictSignal(t *testing.T) {
	fs := newFakeStore()
	now := time.Now()
	fs.signalDevices = []store.SignalDeviceRow{
		{ID: "aa:00:00:00:00:01", Class: "managed", Verified: true, LastSeen: now, IPs: []string{"192.168.100.7"}},
		{ID: "aa:00:00:00:00:02", Class: "managed", Verified: true, LastSeen: now, IPs: []string{"192.168.100.7"}},
	}
	out := nr033Get(t, fs)
	if len(out.Signals) != 2 {
		t.Fatalf("сигналов %d, хочу по одному на устройство: %+v", len(out.Signals), out.Signals)
	}
	for _, s := range out.Signals {
		if s.Kind != SignalIPConflict || s.Status != NodeAttention {
			t.Fatalf("сигнал %+v, хочу ip_conflict/attention", s)
		}
		if !strings.Contains(s.Text, "192.168.100.7") {
			t.Fatalf("в тексте нет адреса: %q", s.Text)
		}
	}
}

// TestNR033SnoozeHidesSignal — «Игнорировать на N дней» прячет
// сигнал до срока; при некорректном сроке — 400.
func TestNR033SnoozeHidesSignal(t *testing.T) {
	fs := newFakeStore()
	fs.signalDevices = []store.SignalDeviceRow{
		{ID: "aa:bb:cc:dd:ee:01", Class: "unknown", IPs: []string{"192.168.100.10"}},
	}
	fs.openAlerts = []store.OpenAlert{{ID: 1, DeviceID: "aa:bb:cc:dd:ee:01", Created: time.Now()}}
	a, err := New(fs, token, mustScope(t), mustLimiter(t), &fakeProber{})
	if err != nil {
		t.Fatalf("api: %v", err)
	}
	h := a.Handler()

	before := nr033Get(t, fs)
	if len(before.Signals) != 1 {
		t.Fatalf("до откладывания сигналов %d, хочу 1", len(before.Signals))
	}

	if rec := do(h, "POST", "/api/signals/snooze", `{"device_id":"aa:bb:cc:dd:ee:01","kind":"unknown_new","days":0}`, bearer); rec.Code != 400 {
		t.Fatalf("snooze на 0 дней: код %d, хочу 400", rec.Code)
	}
	if rec := do(h, "POST", "/api/signals/snooze", `{"device_id":"aa:bb:cc:dd:ee:01","kind":"unknown_new","days":7}`, bearer); rec.Code != 200 {
		t.Fatalf("snooze на 7 дней: код %d: %s", rec.Code, rec.Body.String())
	}
	if fs.lastSnooze != [3]string{"aa:bb:cc:dd:ee:01", "unknown_new", ActorOwner} {
		t.Fatalf("snooze не дошёл до хранилища: %+v", fs.lastSnooze)
	}

	after := nr033Get(t, fs)
	if len(after.Signals) != 0 {
		t.Fatalf("после откладывания сигналов %d, хочу 0", len(after.Signals))
	}
	// Решений у узла тоже нет.
	if len(after.Statuses) != 1 || after.Statuses[0].Decisions != 0 {
		t.Fatalf("статусы после откладывания: %+v", after.Statuses)
	}
}

// TestNR033ResolveStatusPriority — статус узла: ■ сильнее ▲, ▲
// сильнее ○, у проверенного устройства без сигналов — ●.
func TestNR033ResolveStatusPriority(t *testing.T) {
	now := time.Now()
	devs := []store.SignalDeviceRow{
		{ID: "aa:00:00:00:00:01", Class: "unknown", Verified: true, LastSeen: now},
		{ID: "aa:00:00:00:00:02", Class: "managed", Verified: true, LastSeen: now.Add(-48 * time.Hour)},
		{ID: "aa:00:00:00:00:03", Class: "managed", Verified: false, LastSeen: now},
		{ID: "aa:00:00:00:00:04", Class: "managed", Verified: true, LastSeen: now},
	}
	signals := []mapSignal{
		{DeviceID: "aa:00:00:00:00:01", Status: NodeProblem, Kind: SignalSecurity},
		{DeviceID: "aa:00:00:00:00:01", Status: NodeAttention, Kind: SignalIPConflict},
		{DeviceID: "aa:00:00:00:00:02", Status: NodeOffline, Kind: SignalNoResponse},
		{DeviceID: "aa:00:00:00:00:04", Status: NodeAttention, Kind: SignalSecurity},
	}
	statuses := resolveStatuses(devs, signals)
	want := map[string]string{
		"aa:00:00:00:00:01": NodeProblem, // ■ сильнее ▲
		"aa:00:00:00:00:02": NodeOffline,
		"aa:00:00:00:00:03": NodeUnverified,
		"aa:00:00:00:00:04": NodeAttention,
	}
	for _, st := range statuses {
		if want[st.ID] != "" && st.Status != want[st.ID] {
			t.Fatalf("узел %s: статус %q, хочу %q", st.ID, st.Status, want[st.ID])
		}
	}
}

// TestNR033DeviceCardFields — расширенная карточка отдаёт
// first_seen/last_seen, оповещения и историю изменений.
func TestNR033DeviceCardFields(t *testing.T) {
	fs := newFakeStore()
	dev := store.DeviceInfo{Manual: false, Verified: false}
	dev.ID = "aa:bb:cc:dd:ee:01"
	dev.MAC = dev.ID
	dev.Class = "unknown"
	dev.IPs = []netip.Addr{netip.MustParseAddr("192.168.100.10")}
	dev.FirstSeen = time.Date(2026, 10, 20, 9, 0, 0, 0, time.UTC)
	dev.LastSeen = time.Date(2026, 10, 26, 9, 0, 0, 0, time.UTC)
	fs.devices[dev.ID] = dev
	fs.openAlerts = []store.OpenAlert{{ID: 5, DeviceID: dev.ID, Created: time.Now()}}
	fs.auditEntries = []store.HistoryEntry{
		{At: time.Now(), Actor: "owner", Action: "device_class", Detail: "unknown → known_no_agent"},
	}

	a, err := New(fs, token, mustScope(t), mustLimiter(t), &fakeProber{})
	if err != nil {
		t.Fatalf("api: %v", err)
	}
	h := a.Handler()
	rec := do(h, "GET", "/api/devices/aa:bb:cc:dd:ee:01", "", bearer)
	if rec.Code != 200 {
		t.Fatalf("код %d: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{
		`"mac":"aa:bb:cc:dd:ee:01"`,
		`"first_seen":"2026-10-20`,
		`"last_seen":"2026-10-26`,
		`"alerts"`,
		`"history"`,
		`"device_class"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("в карточке нет %s:\n%s", want, body)
		}
	}
}
