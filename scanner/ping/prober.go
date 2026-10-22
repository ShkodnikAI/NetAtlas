package ping

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"
)

// ReadTimeout — дедлайн ожидания эхо-ответа на один пробник.
const ReadTimeout = time.Second

// Prober — проверка живости адреса. alive=false при err==nil значит
// «хост молчит» (таймаут); err!=nil — ошибка инфраструктуры или контекста.
type Prober interface {
	Ping(ctx context.Context, dst netip.Addr) (rtt time.Duration, alive bool, err error)
}

type waiter struct {
	dst     netip.Addr
	payload []byte
	ch      chan time.Time
}

// ICMPProber — Prober по ICMP echo через raw-сокет. Один сокет на все
// опросы: одна горутина-читатель раздаёт ответы ожидающим по номеру
// (seq) с проверкой адреса назначения и полезной нагрузки.
type ICMPProber struct {
	conn net.PacketConn
	id   uint16

	mu      sync.Mutex
	seq     uint16
	waiters map[uint16]*waiter
	closed  bool
}

// NewICMPProber открывает ICMP raw-сокет. Без прав (Linux: root или
// cap_net_raw; Windows: запуск от администратора) вернёт ошибку
// с подсказкой — это валидный исход для машины без прав.
func NewICMPProber() (*ICMPProber, error) {
	conn, err := net.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return nil, fmt.Errorf("ping: не удалось открыть ICMP-сокет (нужны права: Linux — root или cap_net_raw, Windows — запуск от администратора): %w", err)
	}
	return newICMPProberConn(conn, uint16(os.Getpid()&0xffff)), nil
}

// newICMPProberConn — внутренний конструктор с инъекцией соединения:
// тесты работают с фейковым net.PacketConn без raw-сокета.
func newICMPProberConn(conn net.PacketConn, id uint16) *ICMPProber {
	p := &ICMPProber{
		conn:    conn,
		id:      id,
		waiters: make(map[uint16]*waiter),
	}
	go p.readLoop()
	return p
}

// Close закрывает сокет и завершает горутину-читатель.
// Ожидающие пробники завершаются по своему таймауту.
func (p *ICMPProber) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return errors.New("ping: пробер уже закрыт")
	}
	p.closed = true
	p.mu.Unlock()
	return p.conn.Close()
}

// Ping отправляет эхо-запрос и ждёт эхо-ответ не дольше ReadTimeout
// и не дольше отмены контекста.
func (p *ICMPProber) Ping(ctx context.Context, dst netip.Addr) (time.Duration, bool, error) {
	if !dst.IsValid() || !dst.Is4() {
		return 0, false, fmt.Errorf("ping: нужен валидный IPv4-адрес, получен %v", dst)
	}
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return 0, false, errors.New("ping: пробер закрыт")
	}
	p.seq++
	seq := p.seq
	w := &waiter{dst: dst, ch: make(chan time.Time, 1)}
	p.waiters[seq] = w
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		delete(p.waiters, seq)
		p.mu.Unlock()
	}()

	start := time.Now()
	payload := make([]byte, 8)
	binary.BigEndian.PutUint64(payload, uint64(start.UnixNano()))
	w.payload = payload

	req := EchoRequest(p.id, seq, payload)
	ip4 := dst.As4()
	addr := &net.IPAddr{IP: net.IP(ip4[:])}
	deadline := time.Now().Add(ReadTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := p.conn.SetWriteDeadline(deadline); err != nil {
		return 0, false, fmt.Errorf("ping: дедлайн записи: %w", err)
	}
	if _, err := p.conn.WriteTo(req, addr); err != nil {
		return 0, false, fmt.Errorf("ping: отправка на %v: %w", dst, err)
	}

	timer := time.NewTimer(ReadTimeout)
	defer timer.Stop()
	select {
	case at := <-w.ch:
		rtt := at.Sub(start)
		if rtt < 0 {
			rtt = 0
		}
		return rtt, true, nil
	case <-timer.C:
		return 0, false, nil
	case <-ctx.Done():
		return 0, false, ctx.Err()
	}
}

// readLoop читает сокет до закрытия: разбирает эхо-ответы и раздаёт
// их ожидающим. Проверки: ID совпадает, seq в таблице ожидающих,
// адрес отправителя равен адресу назначения, полезная нагрузка совпадает.
func (p *ICMPProber) readLoop() {
	buf := make([]byte, 1500)
	for {
		n, from, err := p.conn.ReadFrom(buf)
		if err != nil {
			return
		}
		rep, err := ParseEchoReply(buf[:n])
		if err != nil {
			continue // не эхо-ответ или битый пакет — не наш случай
		}
		if rep.ID != p.id {
			continue
		}
		src, ok := addrFromNet(from)
		if !ok {
			continue
		}
		p.mu.Lock()
		w, ok2 := p.waiters[rep.Seq]
		match := ok2 && src == w.dst && equalBytes(rep.Payload, w.payload)
		if match {
			w.ch <- time.Now()
		}
		p.mu.Unlock()
	}
}

func addrFromNet(a net.Addr) (netip.Addr, bool) {
	var ip net.IP
	switch v := a.(type) {
	case *net.IPAddr:
		ip = v.IP
	case *net.UDPAddr:
		ip = v.IP
	default:
		return netip.Addr{}, false
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Addr{}, false
	}
	addr = addr.Unmap()
	if !addr.Is4() {
		return netip.Addr{}, false
	}
	return addr, true
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
