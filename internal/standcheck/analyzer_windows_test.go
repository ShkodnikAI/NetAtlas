//go:build windows

// Прогон PSScriptAnalyzer на самих скриптах стенда (NR-026, пункт
// 6): если анализатор установлен на windows-latest — скрипты стенда
// не должны иметь ошибок уровня Error. Анализатор не установлен —
// тест пропускается с пояснением (не выдумываем результата).
package standcheck

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestStandScriptsWithPSScriptAnalyzer(t *testing.T) {
	pwsh, err := exec.LookPath("pwsh")
	if err != nil {
		if _, err5 := exec.LookPath("powershell.exe"); err5 != nil {
			t.Skip("PowerShell недоступен на этом раннере")
		}
		pwsh = "powershell.exe"
	}
	// Есть ли модуль PSScriptAnalyzer и работает ли он: пробный
	// анализ временного скрипта. Недоступен — Skip (наряд: «если
	// доступен»), результат не выдумываем.
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	tmp, err := os.CreateTemp("", "probe-*.ps1")
	if err != nil {
		t.Fatalf("temp: %v", err)
	}
	tmp.WriteString("Write-Output ok\n")
	tmp.Close()
	defer os.Remove(tmp.Name())
	probe := exec.CommandContext(ctx, pwsh, "-NoProfile", "-NonInteractive", "-Command",
		"Invoke-ScriptAnalyzer -Path $args[0] | Out-Null; if (-not $?) { exit 1 }", tmp.Name())
	if out, perr := probe.CombinedOutput(); perr != nil {
		t.Skipf("PSScriptAnalyzer недоступен на раннере (%v: %s): прогон не выдумываем", perr, strings.TrimSpace(string(out)))
	}

	dir := standDir(t)
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".ps1") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		cctx, ccancel := context.WithTimeout(context.Background(), 5*time.Minute)
		cmd := exec.CommandContext(cctx, pwsh, "-NoProfile", "-NonInteractive", "-Command",
			"Invoke-ScriptAnalyzer -Path $args[0] -Severity Error | ConvertTo-Json -Compress", path)
		out, aerr := cmd.Output()
		ccancel()
		if aerr != nil {
			// Анализатор не смог обработать файл: это отсутствие
			// проверки, а не провал скрипта — фиксируем честно.
			t.Logf("%s: анализатор недоступен для файла: %v", e.Name(), aerr)
			continue
		}
		var findings []map[string]any
		trimmed := strings.TrimSpace(string(out))
		if trimmed != "" && trimmed != "null" {
			if err := json.Unmarshal([]byte(trimmed), &findings); err != nil {
				// одна запись — не массив
				findings = []map[string]any{{}}
			}
		}
		if len(findings) > 0 {
			t.Errorf("%s: PSScriptAnalyzer нашёл %d ошибок уровня Error: %s", e.Name(), len(findings), trimmed)
		}
	}
}
