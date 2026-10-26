package pipeline

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/ShkodnikAI/NetAtlas/internal/model"
	"github.com/ShkodnikAI/NetAtlas/scanner/arp"
	"github.com/ShkodnikAI/NetAtlas/scanner/ping"
)

// fakeResolver — подставной резолвер обратного DNS (NR-030).
type fakeResolver struct {
	mu      sync.Mutex
	queries []string
	answers map[string][]string
	fail    map[string]bool
}

func (r *fakeResolver) LookupAddr(_ context.Context, addr string) ([]string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.queries = append(r.queries, addr)
	if r.fail[addr] {
		return nil, errors.New("резолвер не ответил")
	}
	if names, ok := r.answers[addr]; ok {
		return names, nil
	}
	return nil, nil
}

func (r *fakeResolver) asked() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.queries...)
}

// noLocal — подставные пустые локальные интерфейсы (герметичность).
func noLocal() func() ([]LocalIface, error) {
	return func() ([]LocalIface, error) { return nil, nil }
}

func fixedHost(name string) func() (string, error) {
	return func() (string, error) { return name, nil }
}

// NR-030 п.2: первое чтение ARP пусто, второе даёт запись — хост,
// ответивший на ping, становится устройством с MAC и наблюдениями
// arp и ping, а не остаётся хостом без MAC.
func TestPipelineARPAgainAfterPing(t *testing.T) {
	calls := 0
	cfg := Config{Scope: scopeFix(t), Limiter: limiterFix(t), Ping: true, NoDNS: true}
	deps := Deps{
		ReadARP: func(ctx context.Context) ([]arp.Entry, error) {
			calls++
			if calls == 1 {
				return nil, nil // до обхода кэш пуст
			}
			return []arp.Entry{{IP: netip.MustParseAddr("10.0.0.5"), MAC: "00:00:00:00:00:05"}}, nil
		},
		NewProber: func() (ping.Prober, func(), error) {
			return &fakeProber{alive: map[string]bool{"10.0.0.5": true}}, func() {}, nil
		},
		ReadLocalIfaces: noLocal(),
		Hostname:        fixedHost("netatlas"),
	}
	res, err := Run(context.Background(), cfg, deps)
	if err != nil {
		t.Fatalf("конвейер: %v", err)
	}
	if calls != 2 {
		t.Fatalf("чтений ARP = %d, хочу 2", calls)
	}
	if res.Counts.Devices != 1 || res.Counts.Hosts != 0 {
		t.Fatalf("счётчики: %+v, хочу устройств 1, хостов 0", res.Counts)
	}
	d := res.Devices[0]
	if d.ID != "00:00:00:00:00:05" {
		t.Fatalf("устройство %q, хочу 00:00:00:00:00:05", d.ID)
	}
	if len(d.IPs) != 1 || d.IPs[0].String() != "10.0.0.5" {
		t.Fatalf("адреса устройства: %v", d.IPs)
	}
	hasARP, hasPing := false, false
	for _, o := range d.Observations {
		switch o.Source {
		case "arp":
			hasARP = true
		case "ping":
			hasPing = true
		}
	}
	if !hasARP || !hasPing {
		t.Fatalf("наблюдения устройства: %+v, хочу arp и ping", d.Observations)
	}
}

// NR-030 п.3: локальные интерфейсы — эта машина появляется в
// результате как устройство с MAC, адресами внутри границ,
// наблюдением local и именем из hostname; живой адрес вливается в
// устройство; интерфейсы вне границ и без MAC устройства не создают.
func TestPipelineLocalInterfaces(t *testing.T) {
	cfg := Config{Scope: scopeFix(t), Limiter: limiterFix(t), Ping: true, NoDNS: true}
	deps := Deps{
		ReadARP: func(ctx context.Context) ([]arp.Entry, error) { return nil, nil },
		NewProber: func() (ping.Prober, func(), error) {
			return &fakeProber{alive: map[string]bool{"10.0.0.7": true}}, func() {}, nil
		},
		ReadLocalIfaces: func() ([]LocalIface, error) {
			return []LocalIface{
				{Name: "Ethernet", MAC: "02:00:00:00:00:07", Addrs: []netip.Addr{
					netip.MustParseAddr("10.0.0.7"),     // внутри границ
					netip.MustParseAddr("192.168.55.7"), // вне границ — не берётся
				}},
				{Name: "Outside", MAC: "02:00:00:00:00:08", Addrs: []netip.Addr{netip.MustParseAddr("192.168.55.8")}},
				{Name: "NoMAC", MAC: "", Addrs: []netip.Addr{netip.MustParseAddr("10.0.0.9")}},
			}, nil
		},
		Hostname: fixedHost("netatlas-server"),
	}
	res, err := Run(context.Background(), cfg, deps)
	if err != nil {
		t.Fatalf("конвейер: %v", err)
	}
	if res.Counts.Devices != 1 || res.Counts.Hosts != 0 {
		t.Fatalf("счётчики: %+v, хочу устройств 1, хостов 0", res.Counts)
	}
	d := res.Devices[0]
	if d.ID != "02:00:00:00:00:07" {
		t.Fatalf("устройство %q, хочу 02:00:00:00:00:07", d.ID)
	}
	if len(d.IPs) != 1 || d.IPs[0].String() != "10.0.0.7" {
		t.Fatalf("адреса: %v, хочу только 10.0.0.7", d.IPs)
	}
	hasLocal, hasPing := false, false
	for _, o := range d.Observations {
		switch o.Source {
		case "local":
			hasLocal = true
		case "ping":
			hasPing = true
		}
	}
	if !hasLocal || !hasPing {
		t.Fatalf("наблюдения: %+v, хочу local и ping", d.Observations)
	}
	foundName := false
	for _, n := range d.Names {
		if n.Source == "local" && n.Name == "netatlas-server" {
			foundName = true
		}
	}
	if !foundName {
		t.Fatalf("имена: %+v, хочу local «netatlas-server»", d.Names)
	}
}

// NR-030 п.4: обратный DNS включён по умолчанию — устройству без
// имён добавляется имя с источником dns.
func TestPipelineReverseDNSInRun(t *testing.T) {
	resolver := &fakeResolver{answers: map[string][]string{"10.0.0.2": {"box.lan."}}}
	cfg := Config{Scope: scopeFix(t), Limiter: limiterFix(t)}
	deps := Deps{
		ReadARP: func(ctx context.Context) ([]arp.Entry, error) {
			return []arp.Entry{{IP: netip.MustParseAddr("10.0.0.2"), MAC: "00:00:00:00:00:02"}}, nil
		},
		DNSResolver:     resolver,
		ReadLocalIfaces: noLocal(),
		Hostname:        fixedHost("netatlas"),
	}
	res, err := Run(context.Background(), cfg, deps)
	if err != nil {
		t.Fatalf("конвейер: %v", err)
	}
	if got := resolver.asked(); len(got) != 1 || got[0] != "10.0.0.2" {
		t.Fatalf("запросы резолвера: %v, хочу только 10.0.0.2", got)
	}
	d := res.Devices[0]
	if len(d.Names) != 1 || d.Names[0].Source != "dns" || d.Names[0].Name != "box.lan" {
		t.Fatalf("имена устройства: %+v, хочу dns «box.lan» (без точки)", d.Names)
	}
}

// NR-030 п.4: no_dns выключает обратный DNS — запросов нет.
func TestPipelineNoDNSOff(t *testing.T) {
	resolver := &fakeResolver{}
	cfg := Config{Scope: scopeFix(t), Limiter: limiterFix(t), NoDNS: true}
	deps := Deps{
		ReadARP: func(ctx context.Context) ([]arp.Entry, error) {
			return []arp.Entry{{IP: netip.MustParseAddr("10.0.0.2"), MAC: "00:00:00:00:00:02"}}, nil
		},
		DNSResolver:     resolver,
		ReadLocalIfaces: noLocal(),
		Hostname:        fixedHost("netatlas"),
	}
	if _, err := Run(context.Background(), cfg, deps); err != nil {
		t.Fatalf("конвейер: %v", err)
	}
	if got := resolver.asked(); len(got) != 0 {
		t.Fatalf("запросы при NoDNS: %v, хочу пусто", got)
	}
}

// NR-030 п.4, юнит: запросы только внутри границ, ошибка резолвера
// не роняет скан, устройство с именами не опрашивается, хост без
// имён опрашивается.
func TestReverseDNSUnit(t *testing.T) {
	resolver := &fakeResolver{
		answers: map[string][]string{"10.0.0.2": {"box.lan."}},
		fail:    map[string]bool{"10.0.0.4": true},
	}
	scope := scopeFix(t)
	limiter := limiterFix(t)
	now := time.Now()

	d1 := mustDev(t, "00:00:00:00:00:01", "10.0.0.1")
	d1.Names = append(d1.Names, model.Name{Source: "netbios", Name: "pc-1"}) // имя уже есть
	d2 := mustDev(t, "00:00:00:00:00:02", "10.0.0.2")
	// Вне-граничный адрес ПЕРВЫМ: без проверки границ он был бы
	// опрошен раньше внутреннего (после успешного ответа — break).
	d2.IPs = []netip.Addr{netip.MustParseAddr("192.168.55.1"), netip.MustParseAddr("10.0.0.2")}
	d3 := mustDev(t, "00:00:00:00:00:03", "10.0.0.3")
	h1 := mustHost(t, "10.0.0.4")

	devices := []model.Device{d1, d2, d3}
	hosts := []model.Host{h1}

	if err := reverseDNS(context.Background(), devices, hosts, scope, limiter, resolver, now); err != nil {
		t.Fatalf("reverseDNS: %v", err)
	}
	// Запросы: 10.0.0.2 (устройство без имён), 10.0.0.3 (без ответа),
	// 10.0.0.4 (хост). Не было: 10.0.0.1 (имя есть) и 192.168.55.1
	// (вне границ; он первый в списке адресов устройства 2).
	asked := resolver.asked()
	if len(asked) != 3 {
		t.Fatalf("запросов %d (%v), хочу 3", len(asked), asked)
	}
	for _, addr := range asked {
		if addr == "10.0.0.1" || addr == "192.168.55.1" {
			t.Fatalf("лишний запрос %q; все: %v", addr, asked)
		}
	}
	if got := devices[1].Names; len(got) != 1 || got[0].Source != "dns" || got[0].Name != "box.lan" {
		t.Fatalf("имена устройства 2: %+v, хочу dns «box.lan»", got)
	}
	if got := devices[0].Names; len(got) != 1 || got[0].Source != "netbios" {
		t.Fatalf("имена устройства 1 изменились: %+v", got)
	}
	if got := devices[2].Names; len(got) != 0 {
		t.Fatalf("устройство 3 получило имя при сбое резолвера: %+v", got)
	}
	if got := hosts[0].Names; len(got) != 0 {
		t.Fatalf("хост получил имя при сбое резолвера: %+v", got)
	}
}

// NR-030 п.2, юнит mergeDevices: слияние по MAC без дублей, вливание
// хоста в устройство, детерминированный порядок.
func TestMergeDevicesUnit(t *testing.T) {
	now := time.Now()
	base := mustDev(t, "00:00:00:00:00:02", "10.0.0.2")
	base.Observations = append(base.Observations, model.Observation{Source: "ping", Seen: now})
	extra1 := mustDev(t, "00:00:00:00:00:02", "10.0.0.2") // тот же MAC: только arp
	extra1.Observations = append(extra1.Observations, model.Observation{Source: "arp", Seen: now})
	extra2 := mustDev(t, "00:00:00:00:00:09", "10.0.0.9") // новое устройство
	extra2.Observations = append(extra2.Observations, model.Observation{Source: "arp", Seen: now})
	extra2.Names = append(extra2.Names, model.Name{Source: "local", Name: "srv"})
	// Новое устройство с адресом МЕНЬШЕ базовых: сортировка должна
	// поставить его первым независимо от порядка входа.
	extra3 := mustDev(t, "00:00:00:00:00:01", "10.0.0.1")
	extra3.Observations = append(extra3.Observations, model.Observation{Source: "arp", Seen: now})

	h1 := mustHost(t, "10.0.0.9") // адрес нового устройства: вливается
	h1.Observations = append(h1.Observations, model.Observation{Source: "ping", Seen: now})
	h2 := mustHost(t, "10.0.0.77") // устройства нет: остаётся хостом
	h2.Observations = append(h2.Observations, model.Observation{Source: "ping", Seen: now})

	devices, hosts := mergeDevices([]model.Device{base}, []model.Host{h1, h2}, []model.Device{extra1, extra2, extra3}, now)

	if len(devices) != 3 || len(hosts) != 1 {
		t.Fatalf("итог: устройств %d, хостов %d; хочу 3 и 1", len(devices), len(hosts))
	}
	// Порядок по первому IP: .1 (из дополнений) раньше .2 и .9 —
	// без сортировки дополнения оставались бы в порядке входа.
	if devices[0].ID != "00:00:00:00:00:01" || devices[1].ID != "00:00:00:00:00:02" || devices[2].ID != "00:00:00:00:00:09" {
		t.Fatalf("порядок устройств: %s, %s, %s", devices[0].ID, devices[1].ID, devices[2].ID)
	}
	// Слияние без дублей: у .2 наблюдения ping и arp по одному разу.
	if got := devices[1].Observations; len(got) != 2 {
		t.Fatalf("наблюдений у .2 = %d (%+v), хочу 2", len(got), got)
	}
	// Хост 10.0.0.9 влит: у .9 наблюдения arp и ping, имя local.
	if got := devices[2].Observations; len(got) != 2 {
		t.Fatalf("наблюдений у .9 = %d (%+v), хочу arp и ping", len(got), got)
	}
	if got := devices[2].Names; len(got) != 1 || got[0].Name != "srv" {
		t.Fatalf("имена у .9: %+v", got)
	}
	// У .1 только собственное наблюдение arp.
	if got := devices[0].Observations; len(got) != 1 || got[0].Source != "arp" {
		t.Fatalf("наблюдений у .1: %+v, хочу только arp", got)
	}
	// Хост 10.0.0.77 остался.
	if hosts[0].IP.String() != "10.0.0.77" {
		t.Fatalf("хост после слияния: %+v", hosts[0])
	}
}

// mustDev — устройство с одним IP для юнит-фикстур.
func mustDev(t *testing.T, mac, ip string) model.Device {
	t.Helper()
	d, err := model.NewDevice(mac)
	if err != nil {
		t.Fatalf("устройство %s: %v", mac, err)
	}
	a := netip.MustParseAddr(ip)
	d.IPs = append(d.IPs, a)
	return d
}

// mustHost — хост по адресу для юнит-фикстур.
func mustHost(t *testing.T, ip string) model.Host {
	t.Helper()
	h, err := model.NewHost(netip.MustParseAddr(ip))
	if err != nil {
		t.Fatalf("хост %s: %v", ip, err)
	}
	return h
}
