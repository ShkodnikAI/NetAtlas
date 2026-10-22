package scanner

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/ShkodnikAI/NetAtlas/scanner/arp"
	"github.com/ShkodnikAI/NetAtlas/scanner/names"
)

type scanTimeoutError struct{}

func (scanTimeoutError) Error() string   { return "scan fake: дедлайн чтения" }
func (scanTimeoutError) Timeout() bool   { return true }
func (scanTimeoutError) Temporary() bool { return true }

// scanFakeConn — фейковый UDP-сокет для интеграционного теста
// (names.Client работает поверх net.PacketConn) с поддержкой дедлайнов.
type scanFakeConn struct {
	mu       sync.Mutex
	onWrite  func(data []byte, addr net.Addr)
	inbox    chan scanReadItem
	closed   bool
	deadline time.Time
}

type scanReadItem struct {
	data []byte
	addr net.Addr
}

func (f *scanFakeConn) ReadFrom(p []byte) (int, net.Addr, error) {
	f.mu.Lock()
	dl := f.deadline
	closed := f.closed
	f.mu.Unlock()
	if closed {
		return 0, nil, net.ErrClosed
	}
	var timer <-chan time.Time
	if !dl.IsZero() {
		timer = time.After(time.Until(dl))
	}
	select {
	case it, ok := <-f.inbox:
		if !ok {
			return 0, nil, net.ErrClosed
		}
		n := copy(p, it.data)
		return n, it.addr, nil
	case <-timer:
		return 0, nil, scanTimeoutError{}
	}
}

func (f *scanFakeConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	f.mu.Lock()
	f.onWrite(append([]byte(nil), p...), addr)
	f.mu.Unlock()
	return len(p), nil
}

func (f *scanFakeConn) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.closed {
		f.closed = true
		close(f.inbox)
	}
	return nil
}

func (f *scanFakeConn) LocalAddr() net.Addr                { return nil }
func (f *scanFakeConn) SetDeadline(t time.Time) error      { return nil }
func (f *scanFakeConn) SetWriteDeadline(t time.Time) error { return nil }

func (f *scanFakeConn) SetReadDeadline(t time.Time) error {
	f.mu.Lock()
	f.deadline = t
	f.mu.Unlock()
	return nil
}

// nbstatResponse собирает NBSTAT-ответ с одним именем.
func nbstatResponse(id uint16, name string) []byte {
	b := []byte{
		byte(id >> 8), byte(id),
		0x80, 0x00, // QR=1
		0x00, 0x01, // QDCOUNT
		0x00, 0x01, // ANCOUNT
		0x00, 0x00, 0x00, 0x00,
		0x20, // метка 32 символа
	}
	// wildcard-имя «*»: 0x2A + паддинг пробелами + суффикс
	for i, v := range []byte("*") {
		_ = i
		_ = v
	}
	star := []byte{'*'}
	for len(star) < names.NBNameLen {
		star = append(star, 0x20)
	}
	star = append(star, 0x00)
	for _, v := range star {
		b = append(b, 'A'+(v>>4), 'A'+(v&0x0f))
	}
	b = append(b, 0x00)
	b = append(b, 0x00, 0x21, 0x00, 0x01) // QTYPE NBSTAT, QCLASS IN
	// Ответ: указатель на offset 12.
	b = append(b, 0xc0, 0x0c)
	b = append(b, 0x00, 0x21, 0x00, 0x01) // RR TYPE NBSTAT, CLASS IN
	b = append(b, 0, 0, 0, 0)             // TTL
	rdata := []byte{1}
	raw := []byte(name)
	for len(raw) < names.NBNameLen {
		raw = append(raw, 0x20)
	}
	rdata = append(rdata, raw...)
	rdata = append(rdata, 0x00, 0x04, 0x00) // суффикс + флаги
	rdata = append(rdata, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01)
	b = append(b, byte(len(rdata)>>8), byte(len(rdata)))
	b = append(b, rdata...)
	return b
}

func TestRunIntegration(t *testing.T) {
	scope, err := NewScope([]string{"192.168.1.0/29"}, false) // .1-.6
	if err != nil {
		t.Fatalf("NewScope: %v", err)
	}
	limiter, _ := NewLimiter(8, 10000, nil)
	now := time.Date(2026, 10, 23, 13, 0, 0, 0, time.UTC)

	// ARP: устройство с MAC aa:bb:cc:00:11:22 на 192.168.1.10 — вне /29!
	// Берём адрес внутри границ: 192.168.1.10 не в /29. Используем 192.168.1.2.
	entries := []arp.Entry{
		{IP: netip.MustParseAddr("192.168.1.2"), MAC: "aa:bb:cc:00:11:22"},
	}

	prober := &fakeProber{alive: map[netip.Addr]bool{
		netip.MustParseAddr("192.168.1.2"): true, // устройство из ARP
		netip.MustParseAddr("192.168.1.4"): true, // хост без MAC
	}}

	// names: NBSTAT отвечает за 192.168.1.2 («PC-ADMIN») и 192.168.1.4
	// («HOST-4»); SSDP — от 192.168.1.2 («Dev/1.0») и от 10.9.9.9 (вне границ).
	conn := &scanFakeConn{inbox: make(chan scanReadItem, 64)}
	conn.onWrite = func(data []byte, addr net.Addr) {
		if udp, ok := addr.(*net.UDPAddr); ok && udp.Port != names.NBPort {
			return // SSDP не отвечаем — проверяется отдельно
		}
		id := binary.BigEndian.Uint16(data[0:2])
		switch addr.String() {
		case "192.168.1.2:137":
			conn.inbox <- scanReadItem{data: nbstatResponse(id, "PC-ADMIN"), addr: addr}
		case "192.168.1.4:137":
			conn.inbox <- scanReadItem{data: nbstatResponse(id, "HOST-4"), addr: addr}
		}
	}
	client := names.NewClient(conn)
	client.NBTimeout = 20 * time.Millisecond
	client.MDNSTimeout = 20 * time.Millisecond
	client.SSDPWindow = 20 * time.Millisecond

	opt := Options{Ping: true, Names: true, Now: now, Prober: prober, NameClient: client}
	res, err := Run(context.Background(), entries, scope, limiter, opt)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if len(res.Devices) != 1 {
		t.Fatalf("устройств = %d, хочу 1", len(res.Devices))
	}
	d := res.Devices[0]
	if d.MAC != "aa:bb:cc:00:11:22" {
		t.Errorf("MAC = %q", d.MAC)
	}
	if len(d.Observations) != 2 {
		t.Fatalf("наблюдений = %d, хочу 2 (arp + ping)", len(d.Observations))
	}
	srcs := map[string]bool{}
	for _, o := range d.Observations {
		srcs[o.Source] = true
	}
	if !srcs["arp"] || !srcs["ping"] {
		t.Errorf("источники наблюдений = %v, хочу arp и ping", srcs)
	}
	if len(d.Names) != 1 || d.Names[0].Source != "netbios" || d.Names[0].Name != "PC-ADMIN" {
		t.Errorf("имена устройства = %+v, хочу [netbios PC-ADMIN]", d.Names)
	}

	if len(res.Hosts) != 1 {
		t.Fatalf("хостов = %d, хочу 1", len(res.Hosts))
	}
	h := res.Hosts[0]
	if h.IP != netip.MustParseAddr("192.168.1.4") {
		t.Errorf("хост IP = %v, хочу 192.168.1.4", h.IP)
	}
	if len(h.Names) != 1 || h.Names[0].Name != "HOST-4" {
		t.Errorf("имена хоста = %+v, хочу [netbios HOST-4]", h.Names)
	}
	if h.RTT != 1500*time.Microsecond {
		t.Errorf("RTT = %v, хочу 1500µs", h.RTT)
	}
}

func TestRunNoNamesNoUDP(t *testing.T) {
	scope, _ := NewScope([]string{"192.168.1.0/29"}, false)
	limiter, _ := NewLimiter(4, 10000, nil)
	now := time.Now()

	writes := 0
	conn := &scanFakeConn{inbox: make(chan scanReadItem, 64)}
	conn.onWrite = func(data []byte, addr net.Addr) {
		writes++
	}
	client := names.NewClient(conn)
	client.SSDPWindow = 10 * time.Millisecond

	opt := Options{Ping: false, Names: false, Now: now, NameClient: client}
	res, err := Run(context.Background(), nil, scope, limiter, opt)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Devices == nil || res.Hosts == nil {
		t.Error("пустой результат должен иметь пустые срезы, не nil")
	}
	if writes != 0 {
		t.Errorf("при Names=false не должно быть UDP-вызовов, получено %d", writes)
	}
}

func TestRunSSDPInScopeOnly(t *testing.T) {
	scope, _ := NewScope([]string{"192.168.1.0/29"}, false)
	limiter, _ := NewLimiter(4, 10000, nil)
	now := time.Now()

	// SSDP отвечает от 192.168.1.5 (в границах) и от 10.9.9.9 (вне).
	// Ответы пушатся только при записи M-SEARCH на порт 1900, чтобы
	// не съедались чтениями NetBIOS.
	conn := &scanFakeConn{inbox: make(chan scanReadItem, 64)}
	client := names.NewClient(conn)
	client.NBTimeout = 10 * time.Millisecond
	client.MDNSTimeout = 10 * time.Millisecond
	client.SSDPWindow = 30 * time.Millisecond

	wrote := false
	conn.onWrite = func(data []byte, addr net.Addr) {
		udp, ok := addr.(*net.UDPAddr)
		if !ok || udp.Port != names.SSDPPort || wrote {
			return // NB-запросы молчат; M-SEARCH отвечаем один раз
		}
		wrote = true
		in1 := netip.MustParseAddr("192.168.1.5").As4()
		out1 := netip.MustParseAddr("10.9.9.9").As4()
		resp := []byte("HTTP/1.1 200 OK\r\nSERVER: Evil/1.0\r\n\r\n")
		conn.inbox <- scanReadItem{data: resp, addr: &net.UDPAddr{IP: net.IP(in1[:]), Port: 1900}}
		conn.inbox <- scanReadItem{data: resp, addr: &net.UDPAddr{IP: net.IP(out1[:]), Port: 1900}}
	}

	// 192.168.1.5 — живой хост без MAC (проверяем, что SSDP-имя дойдёт
	// до хоста, а ответ вне границ — нет).
	prober := &fakeProber{alive: map[netip.Addr]bool{
		netip.MustParseAddr("192.168.1.5"): true,
	}}
	opt := Options{Ping: true, Names: true, Now: now, Prober: prober, NameClient: client}
	res, err := Run(context.Background(), nil, scope, limiter, opt)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.Hosts) != 1 {
		t.Fatalf("хостов = %d, хочу 1", len(res.Hosts))
	}
	namesList := res.Hosts[0].Names
	if len(namesList) != 1 || namesList[0].Source != "ssdp" || namesList[0].Name != "Evil/1.0" {
		t.Errorf("имена хоста = %+v, хочу [ssdp Evil/1.0]", namesList)
	}
}

func TestRunOptionMismatch(t *testing.T) {
	scope, _ := NewScope([]string{"192.168.1.0/29"}, false)
	limiter, _ := NewLimiter(2, 10000, nil)

	if _, err := Run(context.Background(), nil, scope, limiter, Options{Ping: true}); err == nil {
		t.Error("Ping без Prober: ожидалась ошибка")
	}
	if _, err := Run(context.Background(), nil, scope, limiter, Options{Names: true}); err == nil {
		t.Error("Names без NameClient: ожидалась ошибка")
	}
}
