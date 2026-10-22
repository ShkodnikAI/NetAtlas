package names

import (
	"net"
	"sync"
	"time"
)

type fakeTimeoutError struct{}

func (fakeTimeoutError) Error() string   { return "fake: дедлайн чтения" }
func (fakeTimeoutError) Timeout() bool   { return true }
func (fakeTimeoutError) Temporary() bool { return true }

type fakeAddr struct{}

func (fakeAddr) Network() string { return "udp" }
func (fakeAddr) String() string  { return "fake" }

type readItem struct {
	data []byte
	addr net.Addr
}

// fakeConn — фейковый net.PacketConn с поддержкой дедлайнов чтения:
// герметичные тесты без реальной сети. onWrite вызывается при каждой
// записи; writeLog копит записанные пакеты.
type fakeConn struct {
	mu       sync.Mutex
	onWrite  func(data []byte, addr net.Addr)
	writeLog [][]byte
	inbox    chan readItem
	done     chan struct{}
	once     sync.Once
	deadline time.Time
}

func newFakeConn(onWrite func(data []byte, addr net.Addr)) *fakeConn {
	return &fakeConn{
		onWrite: onWrite,
		inbox:   make(chan readItem, 64),
		done:    make(chan struct{}),
	}
}

func (f *fakeConn) ReadFrom(p []byte) (int, net.Addr, error) {
	f.mu.Lock()
	dl := f.deadline
	f.mu.Unlock()
	var timer <-chan time.Time
	if !dl.IsZero() {
		timer = time.After(time.Until(dl))
	}
	select {
	case it := <-f.inbox:
		n := copy(p, it.data)
		return n, it.addr, nil
	case <-f.done:
		return 0, nil, net.ErrClosed
	case <-timer:
		return 0, nil, fakeTimeoutError{}
	}
}

func (f *fakeConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	f.mu.Lock()
	select {
	case <-f.done:
		f.mu.Unlock()
		return 0, net.ErrClosed
	default:
	}
	cp := append([]byte(nil), p...)
	f.writeLog = append(f.writeLog, cp)
	onWrite := f.onWrite
	f.mu.Unlock()
	if onWrite != nil {
		onWrite(cp, addr)
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

func (f *fakeConn) LocalAddr() net.Addr                { return fakeAddr{} }
func (f *fakeConn) SetDeadline(t time.Time) error      { return nil }
func (f *fakeConn) SetWriteDeadline(t time.Time) error { return nil }

func (f *fakeConn) SetReadDeadline(t time.Time) error {
	f.mu.Lock()
	f.deadline = t
	f.mu.Unlock()
	return nil
}
