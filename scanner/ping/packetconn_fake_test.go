package ping

import (
	"net"
	"sync"
	"time"
)

type fakeAddr struct{}

func (fakeAddr) Network() string { return "ip4" }
func (fakeAddr) String() string  { return "fake" }

type readItem struct {
	data []byte
	addr net.Addr
}

// fakeConn — фейковый net.PacketConn: герметичные тесты без raw-сокета.
// onWrite вызывается при каждой записи — тест может ответить пакетом;
// writeLog копит все записанные пакеты для проверок.
type fakeConn struct {
	mu       sync.Mutex
	onWrite  func(data []byte, addr net.Addr)
	writeLog [][]byte
	inbox    chan readItem
	done     chan struct{}
	once     sync.Once
}

func newFakeConn(onWrite func(data []byte, addr net.Addr)) *fakeConn {
	return &fakeConn{
		onWrite: onWrite,
		inbox:   make(chan readItem, 64),
		done:    make(chan struct{}),
	}
}

func (f *fakeConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case it := <-f.inbox:
		n := copy(p, it.data)
		return n, it.addr, nil
	case <-f.done:
		return 0, nil, net.ErrClosed
	}
}

func (f *fakeConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := append([]byte(nil), p...)
	f.writeLog = append(f.writeLog, cp)
	if f.onWrite != nil {
		f.onWrite(cp, addr)
	}
	return len(p), nil
}

func (f *fakeConn) Close() error {
	f.once.Do(func() { close(f.done) })
	return nil
}

func (f *fakeConn) writes() [][]byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([][]byte(nil), f.writeLog...)
}

func (f *fakeConn) LocalAddr() net.Addr               { return fakeAddr{} }
func (f *fakeConn) SetDeadline(t time.Time) error     { return nil }
func (f *fakeConn) SetReadDeadline(t time.Time) error { return nil }
func (f *fakeConn) SetWriteDeadline(t time.Time) error {
	return nil
}
