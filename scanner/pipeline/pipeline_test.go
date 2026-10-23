package pipeline

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ShkodnikAI/NetAtlas/internal/model"
	"github.com/ShkodnikAI/NetAtlas/scanner"
	"github.com/ShkodnikAI/NetAtlas/scanner/arp"
	"github.com/ShkodnikAI/NetAtlas/scanner/dhcp"
	"github.com/ShkodnikAI/NetAtlas/scanner/ping"
	"github.com/ShkodnikAI/NetAtlas/scanner/snmp"
)

// fakeConn — подставной net.PacketConn: считает отправки по адресам,
// чтение всегда тишина (таймаут).
type fakeConn struct {
	mu       sync.Mutex
	writes   map[string]int
	deadline time.Time
}

func newFakeConn() *fakeConn {
	return &fakeConn{writes: map[string]int{}}
}

func (c *fakeConn) ReadFrom(p []byte) (int, net.Addr, error) {
	if d := time.Until(c.deadline); d > 0 {
		time.Sleep(d)
	}
	return 0, nil, os.ErrDeadlineExceeded // таймаут: трактуется как тишина
}

func (c *fakeConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writes[addr.String()]++
	return len(b), nil
}

func (c *fakeConn) Close() error                  { return nil }
func (c *fakeConn) LocalAddr() net.Addr           { return nil }
func (c *fakeConn) SetDeadline(t time.Time) error { return nil }
func (c *fakeConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadline = t
	c.mu.Unlock()
	return nil
}
func (c *fakeConn) SetWriteDeadline(t time.Time) error { return nil }

func (c *fakeConn) total() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, v := range c.writes {
		n += v
	}
	return n
}

func (c *fakeConn) to(ip string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for addr, v := range c.writes {
		if strings.HasPrefix(addr, ip+":") {
			n += v
		}
	}
	return n
}

// fakeProber — подставной пробер: живы помеченные адреса.
type fakeProber struct {
	alive map[string]bool
}

func (p *fakeProber) Ping(_ context.Context, dst netip.Addr) (time.Duration, bool, error) {
	if p.alive == nil {
		return 0, false, nil
	}
	return 2 * time.Millisecond, p.alive[dst.String()], nil
}

// fakeWalker — подставной SNMP-walker: собирает цели (Collect зовёт
// Walk несколько раз — считаем уникальные адреса).
type fakeWalker struct {
	target netip.Addr
	seen   *map[netip.Addr]bool
	mu     *sync.Mutex
}

func (w *fakeWalker) Get(ctx context.Context, oids ...string) ([]snmp.PDU, error) {
	return nil, nil
}

func (w *fakeWalker) Walk(ctx context.Context, root string, fn func(snmp.PDU) error) error {
	w.mu.Lock()
	(*w.seen)[w.target] = true
	w.mu.Unlock()
	return nil
}

func (w *fakeWalker) Close() error { return nil }

// scopeFix — границы теста: 10.0.0.0/24.
func scopeFix(t *testing.T) *scanner.Scope {
	t.Helper()
	s, err := scanner.NewScope([]string{"10.0.0.0/24"}, false)
	if err != nil {
		t.Fatalf("scope: %v", err)
	}
	return s
}

func limiterFix(t *testing.T) *scanner.Limiter {
	t.Helper()
	l, err := scanner.NewLimiter(4, 1000, nil)
	if err != nil {
		t.Fatalf("limiter: %v", err)
	}
	return l
}

// arpFix — два устройства: обычное и «гость».
func arpFix() []arp.Entry {
	return []arp.Entry{
		{IP: netip.MustParseAddr("10.0.0.2"), MAC: "00:00:00:00:00:02"},
		{IP: netip.MustParseAddr("10.0.0.3"), MAC: "00:00:00:00:00:03"},
	}
}

// Конвейер на подставных зависимостях: стадии и счётчики.
func TestPipelineStagesAndCounters(t *testing.T) {
	var stages []string
	seen := map[netip.Addr]bool{}
	var mu sync.Mutex
	cfg := Config{
		Scope:       scopeFix(t),
		Limiter:     limiterFix(t),
		Ping:        true,
		SNMPTargets: []netip.Addr{netip.MustParseAddr("10.0.0.2")},
		SNMPAuth:    snmp.Auth{V2C: true, Community: "public"},
		OnStage: func(s string) {
			mu.Lock()
			stages = append(stages, s)
			mu.Unlock()
		},
	}
	deps := Deps{
		ReadARP: func(ctx context.Context) ([]arp.Entry, error) { return arpFix(), nil },
		NewProber: func() (ping.Prober, func(), error) {
			return &fakeProber{alive: map[string]bool{"10.0.0.2": true}}, func() {}, nil
		},
		NewNameConn: func() (net.PacketConn, error) { return newFakeConn(), nil },
		NewWalker: func(target netip.Addr, _ snmp.Auth) (snmp.Walker, error) {
			return &fakeWalker{target: target, seen: &seen, mu: &mu}, nil
		},
	}
	res, err := Run(context.Background(), cfg, deps)
	if err != nil {
		t.Fatalf("конвейер: %v", err)
	}
	if got := strings.Join(stages, ","); got != "arp,ping,snmp,topology" {
		t.Fatalf("стадии = %q, хочу arp,ping,snmp,topology", got)
	}
	if res.Counts.Devices != 2 {
		t.Fatalf("устройств = %d, хочу 2", res.Counts.Devices)
	}
	// Живое устройство получило наблюдение ping.
	found := false
	for _, d := range res.Devices {
		if d.ID == "00:00:00:00:00:02" {
			for _, o := range d.Observations {
				if o.Source == "ping" {
					found = true
				}
			}
		}
	}
	if !found {
		t.Fatalf("живое устройство без наблюдения ping: %+v", res.Devices)
	}
	if res.Counts.SNMPTargets != 1 || len(seen) != 1 || !seen[netip.MustParseAddr("10.0.0.2")] {
		t.Fatalf("SNMP: целей %d, walker видел %v", res.Counts.SNMPTargets, seen)
	}
	if res.Topology.Nodes == nil {
		t.Fatalf("топология пустая-nil")
	}
}

// Гость («известный без агента») не опрашивается по именам и SNMP:
// только ARP/ping и данные аренд.
func TestPipelineSkipsGuests(t *testing.T) {
	conn := newFakeConn()
	seen := map[netip.Addr]bool{}
	var mu sync.Mutex
	cfg := Config{
		Scope:        scopeFix(t),
		Limiter:      limiterFix(t),
		Names:        true,
		SNMPTargets:  []netip.Addr{netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("10.0.0.3")},
		SNMPAuth:     snmp.Auth{V2C: true, Community: "public"},
		SkipDeepMACs: map[string]bool{"00:00:00:00:00:03": true}, // гость
	}
	deps := Deps{
		ReadARP:     func(ctx context.Context) ([]arp.Entry, error) { return arpFix(), nil },
		NewNameConn: func() (net.PacketConn, error) { return conn, nil },
		NewWalker: func(target netip.Addr, _ snmp.Auth) (snmp.Walker, error) {
			return &fakeWalker{target: target, seen: &seen, mu: &mu}, nil
		},
	}
	res, err := Run(context.Background(), cfg, deps)
	if err != nil {
		t.Fatalf("конвейер: %v", err)
	}
	// Имена: гостевой IP не опрашивался ни по NetBIOS (137), ни по
	// mDNS (5353); обычный — опрошен.
	if got := conn.to("10.0.0.3"); got != 0 {
		t.Fatalf("гость получил %d запросов имён, хочу 0", got)
	}
	if got := conn.to("10.0.0.2"); got == 0 {
		t.Fatalf("обычное устройство не опрошено по именам")
	}
	// SNMP: walker вызван только для обычного устройства.
	mu.Lock()
	defer mu.Unlock()
	if seen[netip.MustParseAddr("10.0.0.3")] {
		t.Fatalf("гость опрошен по SNMP: %v", seen)
	}
	if len(seen) != 1 || !seen[netip.MustParseAddr("10.0.0.2")] {
		t.Fatalf("walker видел %v, хочу только 10.0.0.2", seen)
	}
	if res.Counts.SNMPTargets != 1 {
		t.Fatalf("целей SNMP = %d, хочу 1 (гость исключён)", res.Counts.SNMPTargets)
	}
}

// Аренды вливаются в конвейер: устройства из файла попадают в итог.
func TestPipelineLeases(t *testing.T) {
	leases := &dhcp.Result{Leases: []dhcp.Lease{
		{MAC: "00:00:00:00:00:09", IP: "10.0.0.9", Hostname: "гостевой-ноутбук"},
	}}
	cfg := Config{Scope: scopeFix(t), Limiter: limiterFix(t), Leases: leases}
	deps := Deps{
		ReadARP:     func(ctx context.Context) ([]arp.Entry, error) { return arpFix(), nil },
		NewNameConn: func() (net.PacketConn, error) { return newFakeConn(), nil },
	}
	res, err := Run(context.Background(), cfg, deps)
	if err != nil {
		t.Fatalf("конвейер: %v", err)
	}
	if res.Counts.Leases != 1 || res.Counts.LeasesSkipped != 0 {
		t.Fatalf("аренды = %+v", res.Counts)
	}
	found := false
	for _, d := range res.Devices {
		if d.ID == "00:00:00:00:00:09" {
			for _, n := range d.Names {
				if n.Source == model.NameSourceDHCP && n.Name == "гостевой-ноутбук" {
					found = true
				}
			}
		}
	}
	if !found {
		t.Fatalf("арендное устройство не в итоге: %+v", res.Devices)
	}
}

// Ошибки конфигурации и зависимостей — до сети.
func TestPipelineValidationErrors(t *testing.T) {
	if _, err := Run(context.Background(), Config{Limiter: limiterFix(t)}, Deps{
		ReadARP: func(ctx context.Context) ([]arp.Entry, error) { return nil, nil },
	}); err == nil || !strings.Contains(err.Error(), "границы") {
		t.Fatalf("nil-Scope: %v", err)
	}
	if _, err := Run(context.Background(), Config{Scope: scopeFix(t)}, Deps{
		ReadARP: func(ctx context.Context) ([]arp.Entry, error) { return nil, nil },
	}); err == nil || !strings.Contains(err.Error(), "ограничитель") {
		t.Fatalf("nil-лимитер: %v", err)
	}
	if _, err := Run(context.Background(), Config{Scope: scopeFix(t), Limiter: limiterFix(t)}, Deps{}); err == nil ||
		!strings.Contains(err.Error(), "ARP-источник") {
		t.Fatalf("nil-ARP: %v", err)
	}
	if _, err := Run(context.Background(), Config{Scope: scopeFix(t), Limiter: limiterFix(t), Ping: true}, Deps{
		ReadARP: func(ctx context.Context) ([]arp.Entry, error) { return nil, nil },
	}); err == nil || !strings.Contains(err.Error(), "пробер") {
		t.Fatalf("ping без пробера: %v", err)
	}
	// Ошибка ARP-источника возвращается.
	if _, err := Run(context.Background(), Config{Scope: scopeFix(t), Limiter: limiterFix(t)}, Deps{
		ReadARP: func(ctx context.Context) ([]arp.Entry, error) { return nil, errors.New("сбой чтения") },
	}); err == nil || !strings.Contains(err.Error(), "сбой чтения") {
		t.Fatalf("ошибка ARP: %v", err)
	}
}
