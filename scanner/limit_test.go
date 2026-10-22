package scanner

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeClock — поддельные часы: Sleep мгновенно продвигает время.
type fakeClock struct {
	mu    sync.Mutex
	now   time.Time
	slept time.Duration
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Sleep(ctx context.Context, d time.Duration) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.slept += d
	c.mu.Unlock()
	return nil
}

func TestNewLimiterErrors(t *testing.T) {
	if _, err := NewLimiter(0, 10, nil); err == nil {
		t.Error("maxParallel=0: ожидалась ошибка")
	}
	if _, err := NewLimiter(-1, 10, nil); err == nil {
		t.Error("maxParallel=-1: ожидалась ошибка")
	}
	if _, err := NewLimiter(2, 0, nil); err == nil {
		t.Error("perSecond=0: ожидалась ошибка")
	}
	if _, err := NewLimiter(2, -5, nil); err == nil {
		t.Error("perSecond=-5: ожидалась ошибка")
	}
	if _, err := NewLimiter(2, 10, nil); err != nil {
		t.Errorf("корректные значения: неожиданная ошибка: %v", err)
	}
}

func TestLimiterParallel(t *testing.T) {
	const (
		maxParallel = 4
		workers     = 100
	)
	l, err := NewLimiter(maxParallel, 100000, nil)
	if err != nil {
		t.Fatalf("NewLimiter: %v", err)
	}
	var (
		active, maxSeen int32
		wg              sync.WaitGroup
	)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			release, err := l.Acquire(context.Background())
			if err != nil {
				t.Errorf("Acquire: %v", err)
				return
			}
			defer release()
			n := atomic.AddInt32(&active, 1)
			for {
				m := atomic.LoadInt32(&maxSeen)
				if n <= m || atomic.CompareAndSwapInt32(&maxSeen, m, n) {
					break
				}
			}
			time.Sleep(time.Millisecond)
			atomic.AddInt32(&active, -1)
		}()
	}
	wg.Wait()
	if maxSeen > maxParallel {
		t.Errorf("пик параллельности %d превышает лимит %d", maxSeen, maxParallel)
	}
}

func TestLimiterRate(t *testing.T) {
	fc := newFakeClock()
	l, err := NewLimiter(2, 5, fc) // интервал 200 мс
	if err != nil {
		t.Fatalf("NewLimiter: %v", err)
	}
	ctx := context.Background()
	start := fc.Now()
	for i := 0; i < 10; i++ {
		release, err := l.Acquire(ctx)
		if err != nil {
			t.Fatalf("Acquire #%d: %v", i+1, err)
		}
		release()
	}
	elapsed := fc.Now().Sub(start)
	// Первый запуск мгновенный, ещё 9 с интервалом 200 мс = 1,8 с.
	if elapsed < 1800*time.Millisecond || elapsed > 2000*time.Millisecond {
		t.Errorf("10 запусков при 5/с заняли %v, хочу от 1,8 с до 2,0 с", elapsed)
	}
}

func TestLimiterCancelledContext(t *testing.T) {
	fc := newFakeClock()
	l, err := NewLimiter(1, 1, fc)
	if err != nil {
		t.Fatalf("NewLimiter: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan struct{})
	var errAcq error
	go func() {
		_, errAcq = l.Acquire(ctx)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Acquire с отменённым контекстом заблокировался")
	}
	if errAcq == nil {
		t.Error("ожидалась ошибка отменённого контекста")
	}
}
