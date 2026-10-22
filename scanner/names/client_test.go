package names

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"
)

var targetIP = netip.MustParseAddr("192.168.1.33")

// fastClient — клиент с короткими таймаутами для герметичных тестов.
func fastClient(conn *fakeConn) *Client {
	c := NewClient(conn)
	c.NBTimeout = 30 * time.Millisecond
	c.MDNSTimeout = 30 * time.Millisecond
	c.SSDPWindow = 50 * time.Millisecond
	return c
}

// queryID извлекает TRN ID из первого записанного пакета.
func queryID(t *testing.T, conn *fakeConn) uint16 {
	t.Helper()
	ws := conn.writes()
	if len(ws) == 0 {
		t.Fatal("ни одного записанного запроса")
	}
	return binary.BigEndian.Uint16(ws[0][0:2])
}

func TestClientNetBIOSName(t *testing.T) {
	var conn *fakeConn
	onWrite := func(data []byte, addr net.Addr) {
		id := binary.BigEndian.Uint16(data[0:2])
		conn.inbox <- readItem{data: buildNBStatResponse(id), addr: addr}
	}
	conn = newFakeConn(onWrite)
	c := fastClient(conn)
	defer c.Close()

	name, ok, err := c.NetBIOSName(context.Background(), targetIP)
	if err != nil || !ok {
		t.Fatalf("NetBIOSName: ok=%v err=%v", ok, err)
	}
	if name != "PC-ADMIN" {
		t.Errorf("имя = %q, хочу PC-ADMIN", name)
	}
}

func TestClientNetBIOSForeignSource(t *testing.T) {
	var conn *fakeConn
	onWrite := func(data []byte, addr net.Addr) {
		id := binary.BigEndian.Uint16(data[0:2])
		foreign := &net.UDPAddr{IP: net.IPv4(10, 9, 9, 9), Port: 137}
		conn.inbox <- readItem{data: buildNBStatResponse(id), addr: foreign}
	}
	conn = newFakeConn(onWrite)
	c := fastClient(conn)
	defer c.Close()

	_, ok, err := c.NetBIOSName(context.Background(), targetIP)
	if err != nil {
		t.Fatalf("NetBIOSName: %v", err)
	}
	if ok {
		t.Error("ответ от чужого адреса не должен считаться именем")
	}
}

func TestClientNetBIOSForeignID(t *testing.T) {
	var conn *fakeConn
	onWrite := func(data []byte, addr net.Addr) {
		id := binary.BigEndian.Uint16(data[0:2]) ^ 0xffff // чужой TRN ID
		conn.inbox <- readItem{data: buildNBStatResponse(id), addr: addr}
	}
	conn = newFakeConn(onWrite)
	c := fastClient(conn)
	defer c.Close()

	_, ok, err := c.NetBIOSName(context.Background(), targetIP)
	if err != nil {
		t.Fatalf("NetBIOSName: %v", err)
	}
	if ok {
		t.Error("ответ с чужим TRN ID не должен считаться именем")
	}
}

func TestClientNetBIOSSilence(t *testing.T) {
	conn := newFakeConn(nil)
	c := fastClient(conn)
	defer c.Close()

	_, ok, err := c.NetBIOSName(context.Background(), targetIP)
	if err != nil {
		t.Fatalf("NetBIOSName: %v", err)
	}
	if ok {
		t.Error("тишина не должна считаться именем")
	}
}

func TestClientNetBIOSCloses(t *testing.T) {
	conn := newFakeConn(nil)
	c := fastClient(conn)
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := c.Close(); err == nil {
		t.Error("повторный Close: ожидалась ошибка")
	}
	if _, _, err := c.NetBIOSName(context.Background(), targetIP); err == nil {
		t.Error("NetBIOSName на закрытом клиенте: ожидалась ошибка")
	}
}

func TestClientMDNSName(t *testing.T) {
	var conn *fakeConn
	onWrite := func(data []byte, addr net.Addr) {
		id := binary.BigEndian.Uint16(data[0:2])
		conn.inbox <- readItem{data: buildMDNSResponse(id), addr: addr}
	}
	conn = newFakeConn(onWrite)
	c := fastClient(conn)
	defer c.Close()

	name, ok, err := c.MDNSName(context.Background(), targetIP)
	if err != nil || !ok {
		t.Fatalf("MDNSName: ok=%v err=%v", ok, err)
	}
	if name != "printer.local" {
		t.Errorf("имя = %q, хочу printer.local", name)
	}
}

func TestClientMDNSSilence(t *testing.T) {
	conn := newFakeConn(nil)
	c := fastClient(conn)
	defer c.Close()

	_, ok, err := c.MDNSName(context.Background(), targetIP)
	if err != nil {
		t.Fatalf("MDNSName: %v", err)
	}
	if ok {
		t.Error("тишина не должна считаться именем")
	}
}

func TestClientInvalidAddr(t *testing.T) {
	conn := newFakeConn(nil)
	c := fastClient(conn)
	defer c.Close()

	if _, _, err := c.NetBIOSName(context.Background(), netip.MustParseAddr("fe80::1")); err == nil {
		t.Error("NetBIOSName IPv6: ожидалась ошибка")
	}
	if _, _, err := c.MDNSName(context.Background(), netip.Addr{}); err == nil {
		t.Error("MDNSName невалидный адрес: ожидалась ошибка")
	}
}

func TestClientSSDP(t *testing.T) {
	var conn *fakeConn
	responses := []struct {
		ip   netip.Addr
		data []byte
	}{
		{netip.MustParseAddr("192.168.1.1"), []byte("HTTP/1.1 200 OK\r\nST: upnp:rootdevice\r\nSERVER: dev1\r\n\r\n")},
		{netip.MustParseAddr("192.168.1.2"), []byte("HTTP/1.1 200 OK\r\nST: ssdp:all\r\nSERVER: dev2\r\n\r\n")},
		{netip.MustParseAddr("192.168.1.1"), []byte("HTTP/1.1 200 OK\r\nST: dup\r\nSERVER: dup\r\n\r\n")}, // дубль
	}
	onWrite := func(data []byte, addr net.Addr) {
		for _, r := range responses {
			ip4 := r.ip.As4()
			conn.inbox <- readItem{data: r.data, addr: &net.UDPAddr{IP: net.IP(ip4[:]), Port: 1900}}
		}
	}
	conn = newFakeConn(onWrite)
	c := fastClient(conn)
	defer c.Close()

	out, err := c.SSDP(context.Background())
	if err != nil {
		t.Fatalf("SSDP: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("респондеров = %d, хочу 2 (дубль отброшен)", len(out))
	}
	ip1 := netip.MustParseAddr("192.168.1.1")
	if out[ip1].Server != "dev1" {
		t.Errorf("первый ответ должен выигрывать: %+v", out[ip1])
	}
}

func TestClientSSDPGarbageIgnored(t *testing.T) {
	var conn *fakeConn
	onWrite := func(data []byte, addr net.Addr) {
		conn.inbox <- readItem{data: []byte("garbage without http"), addr: addr}
		conn.inbox <- readItem{data: []byte("HTTP/1.1 200 OK\r\nSERVER: dev\r\n\r\n"), addr: addr}
	}
	conn = newFakeConn(onWrite)
	c := fastClient(conn)
	defer c.Close()

	out, err := c.SSDP(context.Background())
	if err != nil {
		t.Fatalf("SSDP: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("респондеров = %d, хочу 1 (мусор отброшен)", len(out))
	}
}
