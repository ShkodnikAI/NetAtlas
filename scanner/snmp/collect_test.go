package snmp

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ShkodnikAI/NetAtlas/internal/model"
)

// fakeWalker — подставной Walker, обслуживаемый текстовыми фикстурами
// из testdata: строка «OID|kind|значение» (kind: i — число, s —
// строка, x — hex-байты, o — OID). Строки с # и пустые пропускаются.
type fakeWalker struct {
	mu        sync.Mutex
	table     map[string]PDU
	order     []string
	getCalls  int
	walkCalls int
}

func loadFixtures(t *testing.T, files ...string) *fakeWalker {
	t.Helper()
	f := &fakeWalker{table: make(map[string]PDU)}
	for _, name := range files {
		data, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			t.Fatalf("фикстура %s: %v", name, err)
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			parts := strings.SplitN(line, "|", 3)
			if len(parts) != 3 {
				t.Fatalf("фикстура %s: строка без трёх полей: %q", name, line)
			}
			oid, kind, val := parts[0], parts[1], parts[2]
			var pdu PDU
			switch kind {
			case "i":
				n, err := strconv.ParseInt(val, 10, 64)
				if err != nil {
					t.Fatalf("фикстура %s: %q: %v", name, line, err)
				}
				pdu = PDU{OID: oid, Kind: KindInt, Value: n}
			case "s":
				pdu = PDU{OID: oid, Kind: KindBytes, Value: []byte(val)}
			case "x":
				b, err := hex.DecodeString(val)
				if err != nil {
					t.Fatalf("фикстура %s: %q: %v", name, line, err)
				}
				pdu = PDU{OID: oid, Kind: KindBytes, Value: b}
			case "o":
				pdu = PDU{OID: oid, Kind: KindOID, Value: val}
			default:
				t.Fatalf("фикстура %s: неизвестный вид %q", name, kind)
			}
			if _, dup := f.table[oid]; !dup {
				f.order = append(f.order, oid)
			}
			f.table[oid] = pdu
		}
	}
	return f
}

func (f *fakeWalker) Get(ctx context.Context, oids ...string) ([]PDU, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f.mu.Lock()
	f.getCalls++
	f.mu.Unlock()
	out := make([]PDU, 0, len(oids))
	for _, oid := range oids {
		if p, ok := f.table[oid]; ok {
			out = append(out, p)
		} else {
			out = append(out, PDU{OID: oid, Kind: KindNoSuch, Value: nil})
		}
	}
	return out, nil
}

func (f *fakeWalker) Walk(ctx context.Context, root string, fn func(PDU) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	f.mu.Lock()
	f.walkCalls++
	f.mu.Unlock()
	for _, oid := range f.order {
		if !strings.HasPrefix(oid, root+".") {
			continue
		}
		if err := fn(f.table[oid]); err != nil {
			return err
		}
	}
	return nil
}

func (f *fakeWalker) Close() error { return nil }

func (f *fakeWalker) calls() (int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.getCalls, f.walkCalls
}

// fullFixtureSet — полный набор: система, порты, Q-BRIDGE, LLDP.
func fullFixtureSet(t *testing.T) *fakeWalker {
	t.Helper()
	return loadFixtures(t, "sys.txt", "ifname.txt", "qbridge.txt",
		"lldp_chassis_subtype.txt", "lldp_chassis_id.txt",
		"lldp_port_subtype.txt", "lldp_port_id.txt", "lldp_sysname.txt")
}

func TestCollectSystemAndPorts(t *testing.T) {
	f := fullFixtureSet(t)
	res, err := Collect(context.Background(), f)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if res.SysName != "sw-core" {
		t.Errorf("sysName = %q, хочу sw-core", res.SysName)
	}
	if res.SysDescr != "Cisco IOS Software, C2960" {
		t.Errorf("sysDescr = %q", res.SysDescr)
	}
	want := []Port{{1, "Gi0/1"}, {2, "Gi0/2"}, {24, "Te0/24"}}
	if len(res.Ports) != len(want) {
		t.Fatalf("портов = %d, хочу %d: %+v", len(res.Ports), len(want), res.Ports)
	}
	for i, p := range want {
		if res.Ports[i] != p {
			t.Errorf("порт #%d = %+v, хочу %+v", i, res.Ports[i], p)
		}
	}
}

func TestCollectFDBQBridge(t *testing.T) {
	f := fullFixtureSet(t)
	res, err := Collect(context.Background(), f)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	want := []model.FdbEntry{
		{MAC: "00:11:22:55:aa:cc", Port: "Gi0/1"},
		{MAC: "00:11:22:55:aa:cd", Port: "Te0/24"},
	}
	if len(res.FDB) != len(want) {
		t.Fatalf("fdb = %+v, хочу %+v", res.FDB, want)
	}
	for i, e := range want {
		if res.FDB[i] != e {
			t.Errorf("fdb #%d = %+v, хочу %+v", i, res.FDB[i], e)
		}
	}
	// Широковещательный, групповой и нулевой порт отброшены, плюс
	// запятая-пустышка не попала: их нет в want.
}

func TestCollectFDBBridgeFallback(t *testing.T) {
	// Нет qbridge.txt — Q-BRIDGE пуст, берём BRIDGE с переводом
	// номера порта моста в ifIndex.
	f := loadFixtures(t, "sys.txt", "ifname.txt", "bridge.txt", "bridge_ifindex.txt",
		"lldp_chassis_subtype.txt", "lldp_chassis_id.txt",
		"lldp_port_subtype.txt", "lldp_port_id.txt", "lldp_sysname.txt")
	res, err := Collect(context.Background(), f)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	want := []model.FdbEntry{
		{MAC: "00:11:22:55:aa:cc", Port: "Gi0/1"},  // порт моста 1 -> ifIndex 1
		{MAC: "00:11:22:55:aa:cd", Port: "Te0/24"}, // порт моста 5 -> ifIndex 24
	}
	if len(res.FDB) != len(want) {
		t.Fatalf("fdb = %+v, хочу %+v", res.FDB, want)
	}
	for i, e := range want {
		if res.FDB[i] != e {
			t.Errorf("fdb #%d = %+v, хочу %+v", i, res.FDB[i], e)
		}
	}
}

func TestCollectLLDP(t *testing.T) {
	f := fullFixtureSet(t)
	res, err := Collect(context.Background(), f)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	want := []model.LldpNeighbor{
		{LocalPort: "Gi0/1", ChassisID: "00:11:22:55:aa:ce", RemotePort: "00:11:22:55:aa:cf", SysName: "sw-core-2"},
		{LocalPort: "Te0/24", ChassisID: "sw2-loc", RemotePort: "Gi0/24"},
	}
	if len(res.LLDP) != len(want) {
		t.Fatalf("lldp = %+v, хочу %+v", res.LLDP, want)
	}
	for i, n := range want {
		if res.LLDP[i] != n {
			t.Errorf("lldp #%d = %+v, хочу %+v", i, res.LLDP[i], n)
		}
	}
}

func TestCollectPortsFallbackIfDescr(t *testing.T) {
	f := loadFixtures(t, "sys.txt", "ifdescr.txt")
	res, err := Collect(context.Background(), f)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(res.Ports) != 2 || res.Ports[0].Name != "GigabitEthernet0/1" || res.Ports[1].Index != 2 {
		t.Fatalf("порты из ifDescr = %+v", res.Ports)
	}
}

func TestCollectGarbageNoPanic(t *testing.T) {
	f := loadFixtures(t, "sys.txt", "garbage.txt")
	res, err := Collect(context.Background(), f)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	// Из мусора берётся только валидное: порт 3 «sp-3»; FDB пуст
	// (все строки отброшены → BRIDGE-запасной ход пуст); LLDP — одна
	// полная строка с hex-идентификаторами.
	if len(res.Ports) != 1 || res.Ports[0].Index != 3 || res.Ports[0].Name != "sp-3" {
		t.Fatalf("порты = %+v, хочу [{3 sp-3}]", res.Ports)
	}
	if len(res.FDB) != 0 {
		t.Fatalf("fdb = %+v, хочу пусто", res.FDB)
	}
	want := model.LldpNeighbor{LocalPort: "2", ChassisID: "0xFF", RemotePort: "0x000000000000", SysName: "sw3"}
	if len(res.LLDP) != 1 || res.LLDP[0] != want {
		t.Fatalf("lldp = %+v, хочу [%+v]", res.LLDP, want)
	}
}

func TestCollectEmptyWalker(t *testing.T) {
	f := loadFixtures(t) // ничего
	res, err := Collect(context.Background(), f)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if res.SysName != "" || len(res.Ports) != 0 || len(res.FDB) != 0 || len(res.LLDP) != 0 {
		t.Errorf("пустая цель должна давать пустой результат: %+v", res)
	}
}

// TestTargetResultJSON — пустые срезы сериализуются как [], не null.
func TestTargetResultJSON(t *testing.T) {
	tr := NewTargetResult(netip.MustParseAddr("192.168.1.2"))
	b, err := json.Marshal(tr)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(b)
	for _, key := range []string{`"ports":[]`, `"fdb":[]`, `"lldp":[]`} {
		if !strings.Contains(s, key) {
			t.Errorf("в JSON нет %s: %s", key, s)
		}
	}
	if strings.Contains(s, "null") {
		t.Errorf("в JSON есть null: %s", s)
	}
}

func TestCheckTargets(t *testing.T) {
	scope, err := newTestScope("192.168.1.0/29")
	if err != nil {
		t.Fatalf("scope: %v", err)
	}
	in := []netip.Addr{netip.MustParseAddr("192.168.1.2"), netip.MustParseAddr("192.168.1.6")}
	if err := CheckTargets(scope, in); err != nil {
		t.Errorf("цели внутри границ: неожиданная ошибка %v", err)
	}
	out := []netip.Addr{netip.MustParseAddr("192.168.1.2"), netip.MustParseAddr("10.9.9.9")}
	err = CheckTargets(scope, out)
	if err == nil {
		t.Fatal("цель вне границ: ожидалась ошибка")
	}
	if !strings.Contains(err.Error(), "10.9.9.9") {
		t.Errorf("в ошибке нет отвергнутого адреса: %v", err)
	}
	if strings.Contains(err.Error(), "192.168.1.2") {
		t.Errorf("в ошибке не должно быть принятых адресов: %v", err)
	}
	if err := CheckTargets(nil, in); err == nil {
		t.Error("nil-scope никого не пропускает: ожидалась ошибка")
	}
}

// countingLimiter считает Acquire и следит за пиковой параллельностью.
type countingLimiter struct {
	mu        sync.Mutex
	acquires  int
	active    int
	maxActive int
}

func (c *countingLimiter) Acquire(ctx context.Context) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c.mu.Lock()
	c.acquires++
	c.active++
	if c.active > c.maxActive {
		c.maxActive = c.active
	}
	c.mu.Unlock()
	return func() {
		c.mu.Lock()
		c.active--
		c.mu.Unlock()
	}, nil
}

// TestLimitedWalkerEveryRequestTakesSlot — каждый запрос (Get и Walk)
// прошёл через слот: число Acquire равно числу запросов walker, пик
// параллельности не выше 1. Тест падает, если убрать Acquire.
func TestLimitedWalkerEveryRequestTakesSlot(t *testing.T) {
	f := fullFixtureSet(t)
	lim := &countingLimiter{}
	if _, err := Collect(context.Background(), NewLimitedWalker(f, lim)); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	gets, walks := f.calls()
	total := gets + walks
	if total == 0 {
		t.Fatal("walker не вызывался вовсе")
	}
	lim.mu.Lock()
	acquires, maxActive := lim.acquires, lim.maxActive
	lim.mu.Unlock()
	if acquires != total {
		t.Errorf("Acquire=%d, запросов walker=%d — запросы идут мимо лимитера", acquires, total)
	}
	if maxActive > 1 {
		t.Errorf("пик слотов %d превышает 1", maxActive)
	}
}

// blockedLimiter держит единственный слот: Acquire висит до отмены.
type blockedLimiter struct{ ch chan struct{} }

func newBlockedLimiter() *blockedLimiter {
	ch := make(chan struct{}, 1)
	ch <- struct{}{} // слот занят снаружи
	return &blockedLimiter{ch: ch}
}

func (b *blockedLimiter) Acquire(ctx context.Context) (func(), error) {
	select {
	case b.ch <- struct{}{}:
		return func() { <-b.ch }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// TestLimitedWalkerBlocksWhenSlotBusy — занятый слот: ни одного
// запроса к walker, Collect завершается по отмене контекста. Тест
// падает, если убрать Acquire.
func TestLimitedWalkerBlocksWhenSlotBusy(t *testing.T) {
	f := fullFixtureSet(t)
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	_, err := Collect(ctx, NewLimitedWalker(f, newBlockedLimiter()))
	if err == nil {
		t.Fatal("слот занят, контекст истёк: ожидалась ошибка Collect")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("ошибка = %v, хочу context.DeadlineExceeded", err)
	}
	gets, walks := f.calls()
	if gets+walks != 0 {
		t.Errorf("при занятом слоте walker вызывался (%d get, %d walk) — запросы мимо лимитера", gets, walks)
	}
}

func TestLimitedWalkerNilLimiter(t *testing.T) {
	f := fullFixtureSet(t)
	if _, err := Collect(context.Background(), NewLimitedWalker(f, nil)); err == nil {
		t.Error("nil-лимитер: ожидалась ошибка запроса")
	}
	if _, err := Collect(context.Background(), nil); err == nil {
		t.Error("nil-walker: ожидалась ошибка")
	}
}

// testScope — минимальный Scope для тестов без импорта scanner.
type testScope struct{ prefix netip.Prefix }

func newTestScope(cidr string) (*testScope, error) {
	p, err := netip.ParsePrefix(cidr)
	if err != nil {
		return nil, fmt.Errorf("testScope: %w", err)
	}
	return &testScope{prefix: p}, nil
}

func (s *testScope) Contains(a netip.Addr) bool { return s.prefix.Contains(a) }
