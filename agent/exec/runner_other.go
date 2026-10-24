//go:build !windows

// На не-Windows платформе агент не запускает задания: powershell.exe
// — среда исполнения целевых машин (Windows). Раннер возвращает
// ошибку среды; тесты используют подставной раннер.
package exec

import (
	"context"
	"errors"
	"time"
)

// NewScriptRunner — на не-Windows всегда отказ среды: реальных
// заданий здесь нет.
func NewScriptRunner() ScriptRunner { return unsupportedRunner{} }

type unsupportedRunner struct{}

func (unsupportedRunner) Run(context.Context, string, time.Duration) (int, []byte, error) {
	return 0, nil, errors.New("exec: исполнение заданий поддерживается только на Windows")
}
