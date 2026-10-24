// Package privcheck — grep-тесты приватности (NR-012): в коде
// агентов нет обращений к вводу с клавиатуры, снимкам экрана и
// буферу обмена. Сканируются не-тестовые .go файлы agent/ и cmd/;
// сами тесты исключены (в них только имена запрещённых функций).
package privcheck

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// bannedFunctions — запрещённые API: ввод с клавиатуры, снимки
// экрана, буфер обмена (инвариант наряда NR-012 и DECISIONS.md).
var bannedFunctions = []string{
	"SetWindowsHookEx",   // перехват ввода
	"GetAsyncKeyState",   // опрос клавиш
	"GetKeyState",        // состояние клавиш
	"keybd_event",        // эмуляция нажатий
	"SendInput",          // эмуляция ввода
	"GetKeyboardState",   // состояние клавиатуры
	"GetKeyboardLayout",  // раскладка (излишняя приватность)
	"BitBlt",             // захват экрана
	"PrintWindow",        // снимок окна
	"StretchBlt",         // захват экрана
	"GetClipboardData",   // буфер обмена
	"OpenClipboard",      // буфер обмена
	"GetDC",              // контекст устройства (захват экрана)
	"GetWindowDC",        // контекст устройства
	"CreateCompatibleDC", // офскрин-захват
}

// scanDirs — каталоги с кодом агентов (где мог бы быть сбор).
func scanDirs() []string {
	return []string{filepath.Join("..", "..", "agent"), filepath.Join("..", "..", "cmd")}
}

// goSources — все не-тестовые .go файлы каталога рекурсивно.
func goSources(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			// Вендорные и временные каталоги не сканируем.
			if base := info.Name(); base == "node_modules" || base == ".git" || base == "spool" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		// Сам privcheck не сканируем: в нём имена запрещённых функций.
		if strings.Contains(path, "privcheck") {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		out[rel] = string(raw)
		return nil
	})
	if err != nil {
		t.Fatalf("сканирование %s: %v", root, err)
	}
	return out
}

// В коде агентов нет ни одного запрещённого API.
func TestNoBannedInputScreenClipboardAPIs(t *testing.T) {
	for _, dir := range scanDirs() {
		for file, src := range goSources(t, dir) {
			for _, banned := range bannedFunctions {
				if strings.Contains(src, banned) {
					t.Errorf("%s/%s: запрещённый API %s (ввод/экран/буфер обмена)", dir, file, banned)
				}
			}
		}
	}
}

// Запрещённые слова отсутствуют в исходнике сборщика активности.
func TestActivityReportFieldsClean(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "agent", "activity", "activity.go"))
	if err != nil {
		t.Fatalf("activity.go: %v", err)
	}
	src := string(raw)
	for _, root := range []string{"keyboard", "keystroke", "screenshot", "clipboard", "password", "keydown"} {
		if strings.Contains(strings.ToLower(src), root) {
			t.Errorf("agent/activity: запрещённый корень %q в исходнике", root)
		}
	}
}

// Активность отправляется только агрегатами: в сборщике нет
// потоковой передачи.
func TestNoRawEventStreaming(t *testing.T) {
	for _, dir := range scanDirs() {
		for file, src := range goSources(t, dir) {
			if !strings.Contains(file, "activity") {
				continue
			}
			for _, banned := range []string{"websocket", "WriteMessage"} {
				if strings.Contains(src, banned) {
					t.Errorf("%s/%s: потоковая передача %s — только агрегаты", dir, file, banned)
				}
			}
		}
	}
}
