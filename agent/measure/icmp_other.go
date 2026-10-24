//go:build !windows

// На не-Windows реальный ICMP в этом наряде не требуется: тесты
// используют подставной пробер (аудитор NR-008).
package measure

import (
	"context"
	"errors"
)

// ErrNotSupported — ICMP-пробер реализован только для Windows.
var ErrNotSupported = errors.New("measure: ICMP-пробер только на Windows")

type otherProber struct{}

// NewProber на не-Windows возвращает ошибку: замеры задержки
// подставляются в тестах.
func NewProber() (*otherProber, error) { return nil, ErrNotSupported }

func (p *otherProber) Close() error { return nil }

func (p *otherProber) Ping(ctx context.Context, host string, attempts int) ([]float64, error) {
	return nil, ErrNotSupported
}
