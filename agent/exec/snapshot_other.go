//go:build !windows

// На не-Windows снапшоттер только сообщает об отсутствии поддержки:
// точки восстановления и метрики придут с целевых машин.
package exec

import (
	"context"
	"errors"
)

// NewSnapshotter — вне Windows поддержка отсутствует (nil нельзя:
// Process проверяет d.Snap != nil и молчит; здесь честная ошибка).
func NewSnapshotter() Snapshotter { return unsupportedSnapshot{} }

type unsupportedSnapshot struct{}

func (unsupportedSnapshot) Checkpoint(context.Context, int64) error {
	return errors.New("exec: точки восстановления поддерживаются только на Windows")
}

func (unsupportedSnapshot) Measure(context.Context) (*float64, error) {
	return nil, errors.New("exec: метрики до/после поддерживаются только на Windows")
}
