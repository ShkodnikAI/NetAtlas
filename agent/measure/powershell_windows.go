//go:build windows

// Запуск PowerShell для сценариев замеров (встроенный текст,
// фиксированные флаги — как в agent/collect).
package measure

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

func runPowerShell(ctx context.Context, body []byte) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", string(body))
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("measure: powershell: %w: %s", err, tail(out))
	}
	return out, nil
}

func tail(b []byte) string {
	const max = 200
	if len(b) > max {
		return strings.TrimSpace(string(b[len(b)-max:]))
	}
	return strings.TrimSpace(string(b))
}
