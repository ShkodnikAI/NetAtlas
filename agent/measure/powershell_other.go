//go:build !windows

// На не-Windows PS-сценарии замеров не исполняются (провайдер
// состояния подставляется в тестах).
package measure

import (
	"context"
	"errors"
)

var errNoPowerShell = errors.New("measure: PowerShell доступен только на Windows")

func runPowerShell(ctx context.Context, body []byte) ([]byte, error) { return nil, errNoPowerShell }
