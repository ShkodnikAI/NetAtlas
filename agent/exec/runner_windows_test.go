//go:build windows

// Реальный запуск только безвредного скрипта на windows-latest
// (наряд NR-025): Write-Output фиксированной строки; ничего
// изменяющего CI не выполняет. Проверяет полный путь раннера:
// временный файл, права, powershell.exe, вывод.
package exec

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestPowerShellRunnerHarmlessScript(t *testing.T) {
	r := NewScriptRunner()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	code, out, err := r.Run(ctx, "Write-Output 'netatlas-exec-smoke-2026'", time.Minute)
	if err != nil {
		t.Fatalf("запуск: %v", err)
	}
	if code != 0 {
		t.Fatalf("код %d: %s", code, out)
	}
	if !strings.Contains(string(out), "netatlas-exec-smoke-2026") {
		t.Fatalf("вывод без ожидаемой строки: %q", out)
	}
}

func TestPowerShellRunnerNonZeroExit(t *testing.T) {
	r := NewScriptRunner()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	code, out, err := r.Run(ctx, "exit 7", time.Minute)
	if err != nil {
		t.Fatalf("запуск: %v", err)
	}
	if code != 7 {
		t.Fatalf("код %d, хочу 7: %s", code, out)
	}
}

func TestPowerShellRunnerTimeout(t *testing.T) {
	r := NewScriptRunner()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	code, out, err := r.Run(ctx, "Start-Sleep -Seconds 30", 3*time.Second)
	if err == nil || !strings.Contains(err.Error(), "таймаут") {
		t.Fatalf("таймаут не сработал: code=%d err=%v out=%s", code, err, out)
	}
}

func TestPowerShellRunnerOutputCapped(t *testing.T) {
	r := NewScriptRunner()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	// Вывод больше лимита: байты сверх предела отбрасываются, память
	// не раздувается.
	code, out, err := r.Run(ctx, "1..300000 | ForEach-Object { Write-Output 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' }", 4*time.Minute)
	if err != nil {
		t.Fatalf("запуск: %v", err)
	}
	_ = code
	if len(out) > MaxOutputBytes+1024 {
		t.Fatalf("вывод не ограничен: %d байт", len(out))
	}
}
