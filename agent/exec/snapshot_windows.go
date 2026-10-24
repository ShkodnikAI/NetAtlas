//go:build windows

// Точка восстановления на Windows: Checkpoint-Computer для
// изменяющих заданий; метрика — базовый счётчик аптайма системы
// (секунды): сравнение «до/после» осмыслено и не требует прав.
package exec

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// WindowsSnapshotter — рабочая реализация Snapshotter.
type WindowsSnapshotter struct {
	// PS — запуск PowerShell (подменяется в тестах; nil — системный).
	PS func(ctx context.Context, args ...string) ([]byte, error)
}

// NewSnapshotter — снапшоттер для текущей ОС (Windows).
func NewSnapshotter() Snapshotter { return WindowsSnapshotter{} }

// Checkpoint создаёт точку восстановления MODIFY_SETTINGS. Ошибка
// (включая отключённую защиту системы) — не отменяет задание:
// вызывающий пишет её в журнал.
func (WindowsSnapshotter) Checkpoint(ctx context.Context, jobID int64) error {
	cctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	desc := fmt.Sprintf("NetAtlas job %d", jobID) // описание фиксированного вида
	cmd := exec.CommandContext(cctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
		"Checkpoint-Computer -Description $args[0] -RestorePointType MODIFY_SETTINGS", desc)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("exec: Checkpoint-Computer: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Measure — аптайм системы в секундах (число «до/после»).
func (WindowsSnapshotter) Measure(ctx context.Context) (*float64, error) {
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
		"([int]([Environment]::TickCount64) / 1000)")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("exec: аптайм: %w", err)
	}
	v, err := strconv.ParseFloat(strings.TrimSpace(string(out)), 64)
	if err != nil {
		return nil, fmt.Errorf("exec: аптайм: %w", err)
	}
	return &v, nil
}
