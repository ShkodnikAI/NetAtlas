// Тест «только чтение» (NR-010): статический разбор всех встроенных
// сценариев PowerShell агента. Разрешены глаголы Get-* и явный белый
// список; появление запрещённого глагола (Set-*, Enable-*,
// Disable-*, New-*, Remove-*, Invoke-* и другие меняющие состояние)
// ломает этот тест. Комментарии не исключение: опасное слово не
// должно появляться в файле вовсе.
package checks

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// forbiddenVerbs — глаголы, меняющие состояние системы или
// исполняющие произвольный код.
var forbiddenVerbs = []string{
	"Set", "Enable", "Disable", "New", "Remove", "Invoke",
	"Start", "Stop", "Restart", "Add", "Clear", "Update",
	"Reset", "Rename", "Copy", "Move", "Mount", "Dismount",
	"Install", "Uninstall", "Register", "Unregister",
	"Initialize", "Push", "Pop", "Export", "Import",
	"Suspend", "Resume", "Lock", "Unlock", "Protect", "Unprotect",
}

// explicitWhitelist — явный белый список: команды, разрешённые
// несмотря на запрещённый глагол. Каждая запись обоснована здесь же.
var explicitWhitelist = map[string]string{
	// Start-Sleep — пауза внутри сценария замеров; ничего не запускает.
	"Start-Sleep": "пауза внутри сценария, состояние не меняет",
}

var forbiddenRe = func() *regexp.Regexp {
	return regexp.MustCompile(`\b(` + strings.Join(forbiddenVerbs, "|") + `)-[A-Za-z][A-Za-z0-9]*`)
}()

func TestScriptsAreReadOnly(t *testing.T) {
	dirs := []string{"scripts", "../../agent/collect/scripts", "../../agent/measure/scripts"}
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("каталог %s: %v", dir, err)
		}
		for _, e := range entries {
			name := e.Name()
			if !strings.HasSuffix(name, ".ps1") {
				continue
			}
			raw, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			if hits := forbiddenIn(string(raw), name); len(hits) > 0 {
				t.Errorf("%s: запрещённые команды (только чтение нарушено): %s", name, strings.Join(hits, ", "))
			}
		}
	}
}

// forbiddenIn ищет запрещённые глаголы в тексте сценария с учётом
// белого списка.
func forbiddenIn(script, name string) []string {
	var hits []string
	seen := map[string]bool{}
	for _, m := range forbiddenRe.FindAllString(script, -1) {
		if seen[m] {
			continue
		}
		seen[m] = true
		if _, ok := explicitWhitelist[m]; ok {
			continue
		}
		hits = append(hits, m)
	}
	return hits
}

func TestWhitelistIsMinimalAndExplained(t *testing.T) {
	// Белый список не должен разрастись молча: каждая запись обязана
	// иметь обоснование, а Start-Sleep остаётся единственным членом.
	if len(explicitWhitelist) != 1 {
		t.Fatalf("белый список изменился: %d записей — проверь, что каждая обоснована в комментарии", len(explicitWhitelist))
	}
	if _, ok := explicitWhitelist["Start-Sleep"]; !ok {
		t.Fatal("Start-Sleep пропал из белого списка — сценарий замеров сломается")
	}
}

func TestDefaultChecksScriptsExist(t *testing.T) {
	// Каждая проверка из DefaultChecks обязана иметь встроенный
	// сценарий: go:embed гарантирует наличие файла, здесь проверяется
	// связка «имя сценария в коде ↔ имя файла».
	for _, c := range DefaultChecks(NewPowerShellRunner()) {
		sc, ok := c.(*scriptCheck)
		if !ok {
			t.Fatalf("проверка %s не scriptCheck", c.Name())
		}
		if _, err := scriptsFS.ReadFile("scripts/" + sc.script + ".ps1"); err != nil {
			t.Errorf("сценарий проверки %s: %v", sc.script, err)
		}
	}
}

// Мутант-фикстура: сценарий с запрещённым глаголом обязан быть
// пойман статическим разбором (мутации M2/M7 в nr010_mutations.sh
// ослабляют разбор — этот тест их ловит).
func TestScriptsAreReadOnlyMutant(t *testing.T) {
	mutant := "# пример нарушения\nSet-SmbServerConfiguration -EnableSMB1Protocol $false\n"
	hits := forbiddenIn(mutant, "mutant.ps1")
	if len(hits) == 0 || hits[0] != "Set-SmbServerConfiguration" {
		t.Fatalf("мутант не пойман: %v", hits)
	}
	// Белый список работает: Start-Sleep разрешён.
	if hits := forbiddenIn("Start-Sleep -Seconds 1\n", "sleep.ps1"); len(hits) != 0 {
		t.Fatalf("Start-Sleep не в белом списке: %v", hits)
	}
}
