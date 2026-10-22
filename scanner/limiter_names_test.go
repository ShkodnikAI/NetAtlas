package scanner

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/ShkodnikAI/NetAtlas/scanner/arp"
	"github.com/ShkodnikAI/NetAtlas/scanner/names"
)

// recordedConn — счётчик UDP-записей по портам назначения: показывает,
// действительно ли запросы отправлялись (или были удержаны лимитером).
type recordedConn struct {
	mu    sync.Mutex
	ports map[int]int
}

func newRecordedConn() *recordedConn {
	return &recordedConn{ports: make(map[int]int)}
}

func (r *recordedConn) record(addr net.Addr) {
	if udp, ok := addr.(*net.UDPAddr); ok {
		r.mu.Lock()
		r.ports[udp.Port]++
		r.mu.Unlock()
	}
}

func (r *recordedConn) total() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, v := range r.ports {
		n += v
	}
	return n
}

// TestRunNamesNilLimiter — Names с nil-лимитером даёт ошибку до
// отправки любого пакета (как в Sweep).
func TestRunNamesNilLimiter(t *testing.T) {
	scope, _ := NewScope([]string{"192.168.1.0/29"}, false)
	entries := []arp.Entry{
		{IP: netip.MustParseAddr("192.168.1.2"), MAC: "aa:bb:cc:00:11:22"},
	}

	rec := newRecordedConn()
	conn := &scanFakeConn{inbox: make(chan scanReadItem, 64)}
	conn.onWrite = func(data []byte, addr net.Addr) {
		rec.record(addr)
	}
	client := names.NewClient(conn)
	client.NBTimeout = 20 * time.Millisecond

	_, err := Run(context.Background(), entries, scope, nil,
		Options{Names: true, NameClient: client})
	if err == nil {
		t.Error("Names без лимитера: ожидалась ошибка")
	}
	if got := rec.total(); got != 0 {
		t.Errorf("при nil-лимитере не должно быть UDP-запросов, отправлено %d", got)
	}
}

// TestRunNamesWaitForFreeSlot — когда единственный слот лимитера занят,
// запросы имён не отправляются, пока слот не освободится; при отмене
// контекста Run возвращает ошибку и ни одного UDP-запроса. Тест
// падает, если убрать Acquire перед запросом имени.
func TestRunNamesWaitForFreeSlot(t *testing.T) {
	scope, _ := NewScope([]string{"192.168.1.0/29"}, false)
	entries := []arp.Entry{
		{IP: netip.MustParseAddr("192.168.1.2"), MAC: "aa:bb:cc:00:11:22"},
	}

	// Клиент отвечает на NBSTAT: без Acquire Run прошёл бы с именем.
	conn := &scanFakeConn{inbox: make(chan scanReadItem, 64)}
	conn.onWrite = func(data []byte, addr net.Addr) {
		if udp, ok := addr.(*net.UDPAddr); ok && udp.Port == names.NBPort {
			id := binary.BigEndian.Uint16(data[0:2])
			conn.inbox <- scanReadItem{data: nbstatResponse(id, "PC-ADMIN"), addr: addr}
		}
	}
	client := names.NewClient(conn)
	client.NBTimeout = 20 * time.Millisecond
	client.MDNSTimeout = 20 * time.Millisecond

	limiter, _ := NewLimiter(1, 10000, nil)
	hold, err := limiter.Acquire(context.Background()) // тест занимает единственный слот
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	defer hold()

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	_, err = Run(ctx, entries, scope, limiter, Options{Names: true, NameClient: client})
	if err == nil {
		t.Fatal("слот занят, контекст истёк: ожидалась ошибка Run")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("ошибка = %v, хочу context.DeadlineExceeded", err)
	}
}

// TestRunNamesCancelledContextNoQueries — при отменённом контексте
// запросы имён не отправляются вовсе. Тест падает, если убрать
// Acquire перед запросом имени.
func TestRunNamesCancelledContextNoQueries(t *testing.T) {
	scope, _ := NewScope([]string{"192.168.1.0/29"}, false)
	entries := []arp.Entry{
		{IP: netip.MustParseAddr("192.168.1.2"), MAC: "aa:bb:cc:00:11:22"},
	}

	rec := newRecordedConn()
	conn := &scanFakeConn{inbox: make(chan scanReadItem, 64)}
	conn.onWrite = func(data []byte, addr net.Addr) {
		rec.record(addr)
		if udp, ok := addr.(*net.UDPAddr); ok && udp.Port == names.NBPort {
			id := binary.BigEndian.Uint16(data[0:2])
			conn.inbox <- scanReadItem{data: nbstatResponse(id, "PC-ADMIN"), addr: addr}
		}
	}
	client := names.NewClient(conn)
	client.NBTimeout = 20 * time.Millisecond
	client.MDNSTimeout = 20 * time.Millisecond

	limiter, _ := NewLimiter(1, 10000, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := Run(ctx, entries, scope, limiter, Options{Names: true, NameClient: client}); err == nil {
		t.Error("отменённый контекст: ожидалась ошибка Run")
	}
	if got := rec.total(); got != 0 {
		t.Errorf("при отменённом контексте не должно быть UDP-запросов, отправлено %d", got)
	}
}

// TestRunSSDPWaitsForSlot — единственный M-SEARCH тоже берёт слот
// лимитера: пока слот занят, M-SEARCH не отправляется. Тест падает,
// если убрать Acquire перед SSDP.
func TestRunSSDPWaitsForSlot(t *testing.T) {
	scope, _ := NewScope([]string{"192.168.1.0/29"}, false)
	// Без ARP-записей и ping разрешение имён по устройствам/хостам не
	// выполняется — Run идёт сразу к SSDP.

	rec := newRecordedConn()
	conn := &scanFakeConn{inbox: make(chan scanReadItem, 64)}
	conn.onWrite = func(data []byte, addr net.Addr) {
		rec.record(addr)
		if udp, ok := addr.(*net.UDPAddr); ok && udp.Port == names.SSDPPort {
			conn.inbox <- scanReadItem{
				data: []byte("HTTP/1.1 200 OK\r\nSERVER: Dev/1.0\r\n\r\n"),
				addr: addr,
			}
		}
	}
	client := names.NewClient(conn)
	client.SSDPWindow = 20 * time.Millisecond

	limiter, _ := NewLimiter(1, 10000, nil)
	hold, err := limiter.Acquire(context.Background())
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	defer hold()

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	if _, err := Run(ctx, nil, scope, limiter, Options{Names: true, NameClient: client}); err == nil {
		t.Fatal("слот занят, контекст истёк: ожидалась ошибка Run")
	}
	if got := rec.total(); got != 0 {
		t.Errorf("M-SEARCH отправлен при занятом слоте (записей: %d), хочу 0", got)
	}
}

// TestRunNamesInFlightWithinLimit — параллельность запросов имён не
// выше лимита: при maxParallel=1 два запроса никогда не в полёте
// одновременно, и все имена при этом разрешаются.
func TestRunNamesInFlightWithinLimit(t *testing.T) {
	scope, _ := NewScope([]string{"192.168.1.0/29"}, false) // .1-.6
	entries := []arp.Entry{
		{IP: netip.MustParseAddr("192.168.1.2"), MAC: "aa:bb:cc:00:11:22"},
		{IP: netip.MustParseAddr("192.168.1.3"), MAC: "aa:bb:cc:00:11:23"},
	}

	var (
		mu        sync.Mutex
		active    int
		maxActive int
	)
	inFlight := func(delta int) {
		mu.Lock()
		active += delta
		if active > maxActive {
			maxActive = active
		}
		mu.Unlock()
	}

	conn := &scanFakeConn{inbox: make(chan scanReadItem, 64)}
	conn.onWrite = func(data []byte, addr net.Addr) {
		udp, ok := addr.(*net.UDPAddr)
		if !ok || udp.Port != names.NBPort {
			return
		}
		id := binary.BigEndian.Uint16(data[0:2])
		inFlight(1)
		// Ответ с задержкой: окно «в полёте» различимо для счётчика.
		time.AfterFunc(3*time.Millisecond, func() {
			conn.inbox <- scanReadItem{data: nbstatResponse(id, "PC"), addr: addr}
			inFlight(-1)
		})
	}
	client := names.NewClient(conn)
	client.NBTimeout = 200 * time.Millisecond
	client.MDNSTimeout = 20 * time.Millisecond
	client.SSDPWindow = 20 * time.Millisecond

	limiter, _ := NewLimiter(1, 10000, nil)
	res, err := Run(context.Background(), entries, scope, limiter, Options{Names: true, NameClient: client})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.Devices) != 2 {
		t.Fatalf("устройств = %d, хочу 2", len(res.Devices))
	}
	for _, d := range res.Devices {
		if len(d.Names) != 1 || d.Names[0].Name != "PC" {
			t.Errorf("имена устройства %v = %+v, хочу [netbios PC]", d.IPs, d.Names)
		}
	}
	if maxActive > 1 {
		t.Errorf("пик запросов в полёте %d превышает лимит 1", maxActive)
	}
}

// TestRunNamesRateLimited — запросы имён идут с частотой лимитера:
// при 5 запусках/с четыре запроса (3 NetBIOS + 1 SSDP) занимают не
// меньше трёх интервалов (600 мс) поддельного времени. Тест падает,
// если убрать Acquire.
func TestRunNamesRateLimited(t *testing.T) {
	scope, _ := NewScope([]string{"192.168.1.0/29"}, false)
	entries := []arp.Entry{
		{IP: netip.MustParseAddr("192.168.1.2"), MAC: "aa:bb:cc:00:11:22"},
		{IP: netip.MustParseAddr("192.168.1.3"), MAC: "aa:bb:cc:00:11:23"},
		{IP: netip.MustParseAddr("192.168.1.4"), MAC: "aa:bb:cc:00:11:24"},
	}

	conn := &scanFakeConn{inbox: make(chan scanReadItem, 64)}
	conn.onWrite = func(data []byte, addr net.Addr) {
		if udp, ok := addr.(*net.UDPAddr); ok && udp.Port == names.NBPort {
			id := binary.BigEndian.Uint16(data[0:2])
			conn.inbox <- scanReadItem{data: nbstatResponse(id, "PC"), addr: addr}
		}
	}
	client := names.NewClient(conn)
	client.NBTimeout = 20 * time.Millisecond
	client.MDNSTimeout = 20 * time.Millisecond
	client.SSDPWindow = 20 * time.Millisecond

	fc := newFakeClock()
	limiter, _ := NewLimiter(1, 5, fc) // интервал 200 мс
	res, err := Run(context.Background(), entries, scope, limiter, Options{Names: true, NameClient: client})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.Devices) != 3 {
		t.Fatalf("устройств = %d, хочу 3", len(res.Devices))
	}
	// 4 запуска (3 NBSTAT + 1 M-SEARCH): первый мгновенный, ещё три
	// с интервалом 200 мс = 600 мс поддельного времени.
	if slept := fc.slept; slept < 600*time.Millisecond {
		t.Errorf("запросы имён израсходовали %v ожидания, хочу не меньше 600 мс (запросы идут мимо лимитера?)", slept)
	}
}
