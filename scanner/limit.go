package scanner

import (
	"context"
	"fmt"
	"sync"
	"time"
)

const (
	// DefaultParallel — значение по умолчанию для числа параллельных задач.
	DefaultParallel = 16
	// DefaultPerSecond — значение по умолчанию для частоты запусков в секунду.
	DefaultPerSecond = 50
)

// Clock — источник времени для Limiter; выделяется для тестов.
type Clock interface {
	Now() time.Time
	Sleep(ctx context.Context, d time.Duration) error
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

func (realClock) Sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Limiter ограничивает параллельность и частоту запусков задач сканера.
type Limiter struct {
	slots chan struct{}
	rate  float64
	clock Clock

	mu   sync.Mutex
	last time.Time // момент выдачи последнего токена
}

// NewLimiter создаёт ограничитель: не более maxParallel параллельных задач
// и не более perSecond запусков в секунду (корзина токенов ёмкостью 1).
// Нулевые и отрицательные значения дают ошибку. nil Clock заменяется
// на реальные часы.
func NewLimiter(maxParallel int, perSecond float64, c Clock) (*Limiter, error) {
	if maxParallel <= 0 {
		return nil, fmt.Errorf("scanner: maxParallel=%d, нужно положительное число", maxParallel)
	}
	if perSecond <= 0 {
		return nil, fmt.Errorf("scanner: perSecond=%v, нужно положительное число", perSecond)
	}
	if c == nil {
		c = realClock{}
	}
	return &Limiter{
		slots: make(chan struct{}, maxParallel),
		rate:  perSecond,
		clock: c,
	}, nil
}

// Acquire блокирует, пока не свободны и лимит параллельных, и лимит частоты.
// Возвращает release — функцию освобождения слота параллельности.
// При отменённом контексте возвращает ошибку, не захватывая слот.
func (l *Limiter) Acquire(ctx context.Context) (func(), error) {
	select {
	case l.slots <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	// Select при готовых обеих ветках выбирает случайно: если контекст
	// уже отменён, слот освобождаем и детерминированно возвращаем ошибку.
	if err := ctx.Err(); err != nil {
		<-l.slots
		return nil, err
	}
	release := func() { <-l.slots }

	interval := time.Duration(float64(time.Second) / l.rate)
	for {
		l.mu.Lock()
		now := l.clock.Now()
		if l.last.IsZero() || !now.Before(l.last.Add(interval)) {
			l.last = now
			l.mu.Unlock()
			return release, nil
		}
		wait := l.last.Add(interval).Sub(now)
		l.mu.Unlock()

		if err := l.clock.Sleep(ctx, wait); err != nil {
			release()
			return nil, err
		}
	}
}
