// Хелпер тестов пакета: конкатенация исходников для grep-тестов.
package activity

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// packageSource — конкатенация исходников пакета (без тестов).
func packageSource(t *testing.T, _ string) string {
	t.Helper()
	dir, err := filepath.Abs(".")
	if err != nil {
		t.Fatalf("путь: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("чтение: %v", err)
	}
	names := []string{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)
	var b strings.Builder
	for _, n := range names {
		raw, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			t.Fatalf("чтение %s: %v", n, err)
		}
		b.Write(raw)
		b.WriteString("\n")
	}
	return b.String()
}
