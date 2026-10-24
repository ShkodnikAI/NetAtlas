//go:build !windows

// Вне Windows сбор активности недоступен: целевые машины — Windows.
// Поля отсутствуют (инвариант наряда: источник, который нельзя
// получить без запрещённых данных, отсутствует).
package activity

import "context"

// Source без сбора вне Windows.
type Source struct{}

// NewSource — заглушка.
func NewSource() *Source { return &Source{} }

// Snap — пустой снимок.
func (c *Source) Snap(context.Context) Snapshot { return Snapshot{} }

// Account — вне Windows нет учётной записи Windows.
func Account(context.Context) (AccountInfo, error) { return AccountInfo{}, nil }
