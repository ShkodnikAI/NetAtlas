package ping

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"testing"
)

// dstIP — адрес, на который «пингуем» в тестах.
var dstIP = netip.MustParseAddr("192.168.1.77")

// replyTo строит эхо-ответ из запроса: тип 0, поле контрольной суммы
// сначала обнуляется — сумма по RFC 1071 считается при нулевом поле.
func replyTo(req []byte) []byte {
	reply := append([]byte(nil), req...)
	reply[0] = 0
	binary.BigEndian.PutUint16(reply[2:4], 0)
	binary.BigEndian.PutUint16(reply[2:4], Checksum(reply))
	return reply
}

func TestPingEcho(t *testing.T) {
	var conn *fakeConn
	onWrite := func(data []byte, addr net.Addr) {
		conn.inbox <- readItem{data: replyTo(data), addr: addr}
	}
	conn = newFakeConn(onWrite)
	p := newICMPProberConn(conn, 0x1111)
	defer p.Close()

	rtt, alive, err := p.Ping(context.Background(), dstIP)
	if err != nil {
		t.Fatalf("Ping: неожиданная ошибка: %v", err)
	}
	if !alive {
		t.Fatal("хост должен быть жив")
	}
	if rtt < 0 {
		t.Errorf("RTT отрицательный: %v", rtt)
	}
}

func TestPingSilence(t *testing.T) {
	conn := newFakeConn(nil) // на запросы никто не отвечает
	p := newICMPProberConn(conn, 0x2222)
	defer p.Close()

	_, alive, err := p.Ping(context.Background(), dstIP)
	if err != nil {
		t.Fatalf("Ping: неожиданная ошибка: %v", err)
	}
	if alive {
		t.Error("молчащий хост не должен быть жив")
	}
}

func TestPingForeignSeq(t *testing.T) {
	// Ответ с чужим номером игнорируется.
	var conn *fakeConn
	onWrite := func(data []byte, addr net.Addr) {
		reply := replyTo(data)
		binary.BigEndian.PutUint16(reply[6:8], 0x7777) // чужой seq
		conn.inbox <- readItem{data: reply, addr: addr}
	}
	conn = newFakeConn(onWrite)
	p := newICMPProberConn(conn, 0x3333)
	defer p.Close()

	_, alive, err := p.Ping(context.Background(), dstIP)
	if err != nil {
		t.Fatalf("Ping: неожиданная ошибка: %v", err)
	}
	if alive {
		t.Error("ответ с чужим seq не должен считаться ответом")
	}
}

func TestPingForeignSource(t *testing.T) {
	// Ответ от чужого адреса игнорируется.
	var conn *fakeConn
	onWrite := func(data []byte, addr net.Addr) {
		foreign := &net.IPAddr{IP: net.IPv4(10, 9, 9, 9)}
		conn.inbox <- readItem{data: replyTo(data), addr: foreign}
	}
	conn = newFakeConn(onWrite)
	p := newICMPProberConn(conn, 0x4444)
	defer p.Close()

	_, alive, err := p.Ping(context.Background(), dstIP)
	if err != nil {
		t.Fatalf("Ping: неожиданная ошибка: %v", err)
	}
	if alive {
		t.Error("ответ от чужого адреса не должен считаться ответом")
	}
}

func TestPingType3Ignored(t *testing.T) {
	// destination unreachable (тип 3) — не эхо-ответ.
	var conn *fakeConn
	onWrite := func(data []byte, addr net.Addr) {
		unreach := []byte{3, 1, 0, 0, 0, 0, 0, 0}
		binary.BigEndian.PutUint16(unreach[2:4], Checksum(unreach))
		conn.inbox <- readItem{data: unreach, addr: addr}
	}
	conn = newFakeConn(onWrite)
	p := newICMPProberConn(conn, 0x5555)
	defer p.Close()

	_, alive, err := p.Ping(context.Background(), dstIP)
	if err != nil {
		t.Fatalf("Ping: неожиданная ошибка: %v", err)
	}
	if alive {
		t.Error("type 3 не должен считаться ответом")
	}
}

func TestPingGarbageNoPanic(t *testing.T) {
	var conn *fakeConn
	onWrite := func(data []byte, addr net.Addr) {
		conn.inbox <- readItem{data: []byte{0xff, 0x00, 0x01}, addr: addr}
	}
	conn = newFakeConn(onWrite)
	p := newICMPProberConn(conn, 0x6666)
	defer p.Close()

	_, alive, err := p.Ping(context.Background(), dstIP)
	if err != nil {
		t.Fatalf("Ping: неожиданная ошибка: %v", err)
	}
	if alive {
		t.Error("мусорный пакет не должен считаться ответом")
	}
}

func TestPingCtxCancel(t *testing.T) {
	conn := newFakeConn(nil)
	p := newICMPProberConn(conn, 0x7777)
	defer p.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := p.Ping(ctx, dstIP); !errors.Is(err, context.Canceled) {
		t.Errorf("ожидалась context.Canceled, получено: %v", err)
	}
}

func TestPingClosedProber(t *testing.T) {
	conn := newFakeConn(nil)
	p := newICMPProberConn(conn, 0x8888)
	if err := p.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, _, err := p.Ping(context.Background(), dstIP); err == nil {
		t.Error("Ping на закрытом пробере: ожидалась ошибка")
	}
	if err := p.Close(); err == nil {
		t.Error("повторный Close: ожидалась ошибка")
	}
}

func TestPingInvalidAddr(t *testing.T) {
	conn := newFakeConn(nil)
	p := newICMPProberConn(conn, 0x9999)
	defer p.Close()

	if _, _, err := p.Ping(context.Background(), netip.Addr{}); err == nil {
		t.Error("невалидный адрес: ожидалась ошибка")
	}
	if _, _, err := p.Ping(context.Background(), netip.MustParseAddr("fe80::1")); err == nil {
		t.Error("IPv6-адрес: ожидалась ошибка")
	}
}

func TestPingConcurrentSequences(t *testing.T) {
	// Три параллельных пробника получают каждый свой ответ.
	var conn *fakeConn
	onWrite := func(data []byte, addr net.Addr) {
		conn.inbox <- readItem{data: replyTo(data), addr: addr}
	}
	conn = newFakeConn(onWrite)
	p := newICMPProberConn(conn, 0xaaaa)
	defer p.Close()

	results := make(chan bool, 3)
	for i := 0; i < 3; i++ {
		go func() {
			_, alive, err := p.Ping(context.Background(), dstIP)
			if err != nil {
				results <- false
				return
			}
			results <- alive
		}()
	}
	for i := 0; i < 3; i++ {
		if alive := <-results; !alive {
			t.Error("параллельный пробник потерял свой ответ")
		}
	}
}
