// Package standcheck — статические проверки скриптов стенда Hyper-V
// (NR-026, пункт 6): у каждого скрипта есть -WhatIf/-Confirm,
// удаляющие команды только с фильтром по префиксу NetAtlas-Test-.
// Тесты читают scripts/hyperv/*.ps1 как текст — работают на любой
// ОС; прогон PSScriptAnalyzer — только на windows-latest, если
// анализатор доступен.
package standcheck

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// standDir — каталог скриптов стенда относительно пакета.
func standDir(t *testing.T) string {
	t.Helper()
	abs, err := filepath.Abs(filepath.Join("..", "..", "scripts", "hyperv"))
	if err != nil {
		t.Fatalf("путь: %v", err)
	}
	if st, err := os.Stat(abs); err != nil || !st.IsDir() {
		t.Fatalf("каталог стенда не найден: %s", abs)
	}
	return abs
}

// standScripts — все *.ps1 стенда.
func standScripts(t *testing.T) map[string]string {
	t.Helper()
	dir := standDir(t)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("чтение: %v", err)
	}
	out := map[string]string{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".ps1") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("чтение %s: %v", e.Name(), err)
		}
		out[e.Name()] = string(raw)
	}
	if len(out) < 4 {
		t.Fatalf("скриптов стенда %d, минимум 4", len(out))
	}
	return out
}

// У каждого скрипта стенда: подтверждение или WhatIf-режим.
func TestEveryScriptHasConfirmOrWhatIf(t *testing.T) {
	for name, src := range standScripts(t) {
		hasParam := strings.Contains(src, "[switch]$Confirm")
		hasShouldProcess := strings.Contains(src, "SupportsShouldProcess")
		hasWhatIfMessage := strings.Contains(src, "WhatIf") // текст режима без -Confirm
		if !hasParam && !hasShouldProcess {
			t.Errorf("%s: нет ни [switch]$Confirm, ни SupportsShouldProcess", name)
		}
		if !hasWhatIfMessage {
			t.Errorf("%s: нет описания режима -WhatIf (без -Confirm скрипт ничего не делает)", name)
		}
	}
}

// Изменяющие скрипты что-то делают только с -Confirm: ветка
// "if (-not $Confirm) … return" присутствует у создающих/удаляющих.
func TestMutatingScriptsRequireConfirm(t *testing.T) {
	for _, name := range []string{"New-TestNetwork.ps1", "Remove-TestNetwork.ps1", "Invoke-ScriptTest.ps1"} {
		src, ok := standScripts(t)[name]
		if !ok {
			t.Fatalf("нет скрипта %s", name)
		}
		if !strings.Contains(src, "if (-not $Confirm)") {
			t.Errorf("%s: нет проверки -Confirm перед действиями", name)
		}
	}
}

// Удаляющие командлеты Hyper-V только с фильтром NetAtlas-Test-.
func TestRemoveCommandsFilteredByPrefix(t *testing.T) {
	for name, src := range standScripts(t) {
		for _, cmd := range []string{"Remove-VM", "Remove-VMSwitch", "Remove-VMSnapshot", "Remove-Item"} {
			if !strings.Contains(src, cmd) {
				continue
			}
			// Контекст вызова: имя от переменной с фильтром префикса
			// или путь каталога стенда.
			hasPrefixContext := strings.Contains(src, "NetAtlas-Test-") &&
				(strings.Contains(src, `"$prefix*"`) || strings.Contains(src, "$prefix*") ||
					strings.Contains(src, "NetAtlas-Test-Disks") || strings.Contains(src, "^NetAtlas-Test-"))
			if !hasPrefixContext {
				t.Errorf("%s: %s без видимого фильтра NetAtlas-Test-", name, cmd)
			}
		}
	}
}

// Удаляющие команды не вызываются с произвольными именами:
// Remove-VM с литералом не с префиксом запрещён.
func TestRemoveVMNotLiteralForeignName(t *testing.T) {
	re := regexp.MustCompile(`Remove-VM\s+-Name\s+"?([^"\n]+)"?`)
	for name, src := range standScripts(t) {
		for _, m := range re.FindAllStringSubmatch(src, -1) {
			arg := strings.TrimSpace(m[1])
			// Допустимо: переменная с фильтром ($vm.Name…), недопустимо:
			// литерал без NetAtlas-Test-.
			if !strings.HasPrefix(arg, "$") && !strings.Contains(arg, "NetAtlas-Test-") {
				t.Errorf("%s: Remove-VM с посторонним именем %q", name, arg)
			}
		}
	}
}

// Изоляция: коммутатор только Internal или Private, External запрещён.
func TestSwitchTypeIsolated(t *testing.T) {
	src, ok := standScripts(t)["New-TestNetwork.ps1"]
	if !ok {
		t.Fatal("нет New-TestNetwork.ps1")
	}
	if strings.Contains(src, "-SwitchType External") {
		t.Error("коммутатор External недопустим: стенд должен быть изолирован")
	}
	if !strings.Contains(src, "ValidateSet('Internal', 'Private')") {
		t.Error("тип коммутатора должен ограничиваться Internal|Private")
	}
}

// PowerShell Direct, метрики и откат в тестовом прогоне.
func TestInvokeScriptTestUsesDirectAndRollback(t *testing.T) {
	src, ok := standScripts(t)["Invoke-ScriptTest.ps1"]
	if !ok {
		t.Fatal("нет Invoke-ScriptTest.ps1")
	}
	for _, want := range []string{"Invoke-Command -VMName", "Restore-VMSnapshot", "Test-Connection", "Get-PSDrive", "Get-Service"} {
		if !strings.Contains(src, want) {
			t.Errorf("Invoke-ScriptTest.ps1: нет %s", want)
		}
	}
	// Валидация имени ВМ по префиксу: чужие ВМ не тестируются.
	if !strings.Contains(src, "ValidatePattern('^NetAtlas-Test-')") {
		t.Error("Invoke-ScriptTest.ps1: имя ВМ не ограничено префиксом NetAtlas-Test-")
	}
}
