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
	// Есть ли модуль PSScriptAnalyzer.
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	check := exec.CommandContext(ctx, pwsh, "-NoProfile", "-NonInteractive", "-Command",
		"if (Get-Module -ListAvailable PSScriptAnalyzer) { 'yes' } else { 'no' }")
	out, err := check.Output()
	if err != nil || strings.TrimSpace(string(out)) != "yes" {
		t.Skip("PSScriptAnalyzer не установлен на раннере: прогон не выдумываем")
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
		out, err := cmd.Output()
		ccancel()
		if err != nil {
			t.Errorf("%s: анализ не удался: %v", e.Name(), err)
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
