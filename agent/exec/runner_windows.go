//go:build windows

// Запуск проверенного скрипта на Windows: временный файл с правами
// только SYSTEM/Administrators, powershell.exe -NoProfile
// -NonInteractive -ExecutionPolicy Bypass -File, удаление после
// выполнения, вывод ограничен, таймаут через контекст.
package exec

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"
)

// PowerShellRunner — рабочая реализация ScriptRunner для Windows.
type PowerShellRunner struct{}

// NewScriptRunner — раннер для текущей ОС (Windows).
func NewScriptRunner() ScriptRunner { return PowerShellRunner{} }

// Run исполняет ровно переданный скрипт. Содержимое попадает в
// процесс только через временный файл; имя файла фиксированного
// шаблона, права — icacls (только SYSTEM и администраторы).
func (PowerShellRunner) Run(ctx context.Context, script string, timeout time.Duration) (int, []byte, error) {
	if timeout <= 0 {
		return 0, nil, errors.New("exec: таймаут не положительный")
	}
	dir, err := os.MkdirTemp("", "netatlas-exec")
	if err != nil {
		return 0, nil, fmt.Errorf("exec: временный каталог: %w", err)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "job.ps1")
	if err := os.WriteFile(path, []byte(script), 0o600); err != nil {
		return 0, nil, fmt.Errorf("exec: временный файл: %w", err)
	}
	// Файл с проверенным содержимым: доступ только SYSTEM и
	// администраторы (аргументы icacls фиксированы).
	if err := restrict(path); err != nil {
		return 0, nil, fmt.Errorf("exec: права временного файла: %w", err)
	}

	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, "powershell.exe",
		"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", path)
	// Предел вывода: stdout и stderr пишут в общий буфер через
	// мьютекс — exec копирует их в отдельных горутинах.
	w := &limitWriter{limit: MaxOutputBytes}
	cmd.Stdout = w
	cmd.Stderr = w
	runErr := cmd.Run()
	if cctx.Err() == context.DeadlineExceeded {
		return 0, w.Bytes(), fmt.Errorf("exec: таймаут задания истёк")
	}
	if runErr != nil {
		var ee *exec.ExitError
		if errors.As(runErr, &ee) {
			return ee.ExitCode(), w.Bytes(), nil // код возврата — не сбой запуска
		}
		return 0, w.Bytes(), fmt.Errorf("exec: powershell: %w", runErr)
	}
	return 0, w.Bytes(), nil
}

// limitWriter — общий буфер stdout/stderr с жёстким пределом:
// сверх лимита байты отбрасываются (вывод не раздувает память).
// Потокобезопасен: exec копирует stdout и stderr параллельно.
type limitWriter struct {
	mu    sync.Mutex
	buf   bytes.Buffer
	limit int
}

func (l *limitWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.buf.Len()+len(p) > l.limit {
		if room := l.limit - l.buf.Len(); room > 0 {
			l.buf.Write(p[:room])
		}
		return len(p), nil // остальное отброшено без ошибки
	}
	return l.buf.Write(p)
}

// Bytes — накопленный вывод (без превышения лимита).
func (l *limitWriter) Bytes() []byte {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]byte(nil), l.buf.Bytes()...)
}
