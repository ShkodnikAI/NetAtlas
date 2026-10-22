package scanner

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/ShkodnikAI/NetAtlas/scanner/ping"
)

func TestHosts24(t *testing.T) {
	scope, err := NewScope([]string{"192.168.1.0/24"}, false)
	if err != nil {
		t.Fatalf("NewScope: %v", err)
	}
	hosts := Hosts(scope)
	if len(hosts) != 254 {
		t.Fatalf("число адресов = %d, хочу 254", len(hosts))
	}
	if hosts[0] != netip.MustParseAddr("192.168.1.1") {
		t.Errorf("первый = %v, хочу 192.168.1.1", hosts[0])
	}
	if hosts[len(hosts)-1] != netip.MustParseAddr("192.168.1.254") {
		t.Errorf("последний = %v, хочу 192.168.1.254", hosts[len(hosts)-1])
	}
}

func TestHosts30(t *testing.T) {
	scope, _ := NewScope([]string{"10.0.0.0/30"}, false)
	hosts := Hosts(scope)
	if len(hosts) != 2 {
		t.Fatalf("число адресов = %d, хочу 2", len(hosts))
	}
	want := []string{"10.0.0.1", "10.0.0.2"}
	for i, w := range want {
		if hosts[i] != netip.MustParseAddr(w) {
			t.Errorf("hosts[%d] = %v, хочу %s", i, hosts[i], w)
		}
	}
}

func TestHosts31And32(t *testing.T) {
	scope, _ := NewScope([]string{"10.0.0.0/31"}, false)
	if hosts := Hosts(scope); len(hosts) != 2 {
		t.Errorf("/31: число адресов = %d, хочу 2 (RFC 3021)", len(hosts))
	}
	scope, _ = NewScope([]string{"10.0.0.7/32"}, false)
	if hosts := Hosts(scope); len(hosts) != 1 {
		t.Errorf("/32: число адресов = %d, хочу 1", len(hosts))
	}
}

func TestHostsOverlapDedup(t *testing.T) {
	scope, err := NewScope([]string{"10.0.0.0/24", "10.0.0.0/23"}, true)
	if err != nil {
		t.Fatalf("NewScope: %v", err)
	}
	hosts := Hosts(scope)
	if len(hosts) != 510 { // /23 даёт 512 минус сеть и broadcast
		t.Errorf("число адресов = %d, хочу 510 (без дублей)", len(hosts))
	}
	for i := 1; i < len(hosts); i++ {
		if !hosts[i-1].Less(hosts[i]) {
			t.Fatalf("порядок не возрастающий на %d: %v затем %v", i, hosts[i-1], hosts[i])
		}
	}
}

func TestHostsNil(t *testing.T) {
	hosts := Hosts(nil)
	if hosts == nil {
		t.Error("Hosts(nil) должен быть пустым срезом, не nil")
	}
	if len(hosts) != 0 {
		t.Errorf("Hosts(nil): длина %d, хочу 0", len(hosts))
	}
}

// fakeProber — герметичный Prober: «живые» адреса заданы таблицей,
// вызовы записываются, активность считается для проверки лимита.
type fakeProber struct {
	mu        sync.Mutex
	alive     map[netip.Addr]bool
	calls     []netip.Addr
	active    int
	maxActive int
	onCall    func(n int) // вызывается после записи вызова
	n         int
}

func (f *fakeProber) Ping(ctx context.Context, dst netip.Addr) (time.Duration, bool, error) {
	f.mu.Lock()
	f.calls = append(f.calls, dst)
	f.active++
	if f.active > f.maxActive {
		f.maxActive = f.active
	}
	f.n++
	n := f.n
	f.mu.Unlock()

	if f.onCall != nil {
		f.onCall(n)
	}
	time.Sleep(2 * time.Millisecond) // имитация ожидания ответа

	f.mu.Lock()
	f.active--
	a := f.alive[dst]
	f.mu.Unlock()
	return 1500 * time.Microsecond, a, nil
}

func (f *fakeProber) calledWith() []netip.Addr {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]netip.Addr(nil), f.calls...)
}

func TestSweepAliveOnly(t *testing.T) {
	scope, _ := NewScope([]string{"192.168.1.0/29"}, false) // .1-.6
	limiter, _ := NewLimiter(8, 10000, nil)
	p := &fakeProber{alive: map[netip.Addr]bool{
		netip.MustParseAddr("192.168.1.2"): true,
		netip.MustParseAddr("192.168.1.5"): true,
	}}
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)

	hosts, err := Sweep(context.Background(), scope, limiter, p, Hosts(scope), now)
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if len(hosts) != 2 {
		t.Fatalf("живых = %d, хочу 2", len(hosts))
	}
	if hosts[0].IP != netip.MustParseAddr("192.168.1.2") || hosts[1].IP != netip.MustParseAddr("192.168.1.5") {
		t.Errorf("порядок или состав неверные: %v, %v", hosts[0].IP, hosts[1].IP)
	}
	for _, h := range hosts {
		if h.RTT != 1500*time.Microsecond {
			t.Errorf("RTT = %v, хочу 1500µs", h.RTT)
		}
		if len(h.Observations) != 1 || h.Observations[0].Source != "ping" || !h.Observations[0].Seen.Equal(now) {
			t.Errorf("наблюдение неверное: %+v", h.Observations)
		}
	}
}

func TestSweepOutOfScopeNotProbed(t *testing.T) {
	scope, _ := NewScope([]string{"192.168.1.0/29"}, false)
	limiter, _ := NewLimiter(8, 10000, nil)
	p := &fakeProber{alive: map[netip.Addr]bool{}}

	hosts := Hosts(scope)
	hosts = append(hosts, netip.MustParseAddr("10.9.9.9")) // вне границ

	if _, err := Sweep(context.Background(), scope, limiter, p, hosts, time.Now()); err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	for _, c := range p.calledWith() {
		if c == netip.MustParseAddr("10.9.9.9") {
			t.Fatalf("адрес вне scope был опрошен: %v", c)
		}
	}
}

func TestSweepParallelBounded(t *testing.T) {
	scope, _ := NewScope([]string{"192.168.1.0/27"}, false) // 30 адресов
	limiter, _ := NewLimiter(4, 10000, nil)
	p := &fakeProber{alive: map[netip.Addr]bool{}}

	if _, err := Sweep(context.Background(), scope, limiter, p, Hosts(scope), time.Now()); err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if p.maxActive > 4 {
		t.Errorf("максимум активных = %d, хочу не больше 4", p.maxActive)
	}
	if len(p.calledWith()) != 30 {
		t.Errorf("опрошено = %d, хочу 30", len(p.calledWith()))
	}
}

func TestSweepCtxCancel(t *testing.T) {
	scope, _ := NewScope([]string{"192.168.1.0/27"}, false)
	limiter, _ := NewLimiter(2, 10000, nil)
	ctx, cancel := context.WithCancel(context.Background())
	p := &fakeProber{alive: map[netip.Addr]bool{}}
	p.onCall = func(n int) {
		if n == 3 {
			cancel()
		}
	}

	hosts, err := Sweep(ctx, scope, limiter, p, Hosts(scope), time.Now())
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("ожидалась context.Canceled, получено: %v", err)
	}
	if len(hosts) != 0 {
		t.Errorf("частичный результат должен быть пустым при отмене до ответов: %d", len(hosts))
	}
	cancel()
}

func TestSweepNilArgs(t *testing.T) {
	scope, _ := NewScope([]string{"192.168.1.0/29"}, false)
	limiter, _ := NewLimiter(2, 10000, nil)
	p := &fakeProber{}
	ctx := context.Background()

	if _, err := Sweep(ctx, nil, limiter, p, nil, time.Now()); err == nil {
		t.Error("nil-Scope: ожидалась ошибка")
	}
	if _, err := Sweep(ctx, scope, nil, p, nil, time.Now()); err == nil {
		t.Error("nil-Limiter: ожидалась ошибка")
	}
	if _, err := Sweep(ctx, scope, limiter, nil, nil, time.Now()); err == nil {
		t.Error("nil-Prober: ожидалась ошибка")
	}
}

func TestSweepEmptyHosts(t *testing.T) {
	scope, _ := NewScope([]string{"192.168.1.0/29"}, false)
	limiter, _ := NewLimiter(2, 10000, nil)
	p := &fakeProber{}

	hosts, err := Sweep(context.Background(), scope, limiter, p, nil, time.Now())
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if hosts == nil || len(hosts) != 0 {
		t.Errorf("пустой вход должен давать пустой срез, не nil: %#v", hosts)
	}
}

// Компиляционная проверка: fakeProber реализует ping.Prober.
var _ ping.Prober = (*fakeProber)(nil)
