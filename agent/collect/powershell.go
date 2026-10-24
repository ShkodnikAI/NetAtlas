package collect

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

//go:embed scripts/osinfo.ps1 scripts/hardware.ps1 scripts/disks.ps1 scripts/network.ps1 scripts/drivers.ps1 scripts/programs.ps1
var scriptsFS embed.FS

// ScriptRunner исполняет встроенный сценарий по имени и отдаёт его
// вывод (JSON). Имя приходит только из кода — текст из сети в
// команду не попадает никогда.
type ScriptRunner interface {
	Run(ctx context.Context, script string) (json.RawMessage, error)
}

// PowerShellRunner — запуск powershell с фиксированным набором
// аргументов и телом встроенного сценария.
type PowerShellRunner struct {
	// Exe подменяется в тестах; в работе — "powershell".
	Exe string
}

// NewPowerShellRunner — раннер по умолчанию.
func NewPowerShellRunner() *PowerShellRunner { return &PowerShellRunner{Exe: "powershell"} }

// Run исполняет сценарий. Ошибки PowerShell возвращаются с хвостом
// stderr; вывод не парсится здесь — его разбирают парсеры сборщиков.
func (r *PowerShellRunner) Run(ctx context.Context, script string) (json.RawMessage, error) {
	if strings.ContainsAny(script, "./\\") {
		return nil, fmt.Errorf("collect: недопустимое имя сценария %q", script)
	}
	body, err := scriptsFS.ReadFile("scripts/" + script + ".ps1")
	if err != nil {
		return nil, fmt.Errorf("collect: сценарий %s: %w", script, err)
	}
	exe := r.Exe
	if exe == "" {
		exe = "powershell"
	}
	cmd := exec.CommandContext(ctx, exe,
		"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", string(body))
	out, err := cmd.Output()
	if err != nil {
		tail := ""
		if ee, ok := err.(*exec.ExitError); ok && len(ee.Stderr) > 0 {
			msg := strings.TrimSpace(string(ee.Stderr))
			if len(msg) > 300 {
				msg = msg[len(msg)-300:]
			}
			tail = ": " + msg
		}
		return nil, fmt.Errorf("collect: powershell %s: %w%s", script, err, tail)
	}
	trimmed := strings.TrimSpace(string(out))
	if trimmed == "" {
		return nil, fmt.Errorf("collect: powershell %s: пустой вывод", script)
	}
	return json.RawMessage(trimmed), nil
}

// arrayFrom — нормализация вывода ConvertTo-Json: объект → массив
// из одного, null/пусто → nil, массив → элементы.
func arrayFrom(raw json.RawMessage) ([]json.RawMessage, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return nil, nil
	}
	switch trimmed[0] {
	case '[':
		var items []json.RawMessage
		if err := json.Unmarshal(raw, &items); err != nil {
			return nil, fmt.Errorf("collect: массив: %w", err)
		}
		return items, nil
	case '{':
		return []json.RawMessage{raw}, nil
	default:
		return nil, fmt.Errorf("collect: вывод не JSON-объект и не массив")
	}
}

// asString — строка или null → строка.
func asString(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return strings.Trim(strings.TrimSpace(string(raw)), `"`)
	}
	return s
}
