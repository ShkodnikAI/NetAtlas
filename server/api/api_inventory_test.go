// Тесты маршрута инвентаря агента и хранилища последних порций (NR-006).
package api

import (
	"net/http"
	"testing"
	"time"

	"github.com/ShkodnikAI/NetAtlas/server/store"
)

// Маршрут отдаёт последний отчёт; у агента без порций — 404.
func TestAgentInventoryRoute(t *testing.T) {
	fs := newFakeStore()
	fs.inventory["agent:one"] = store.InventoryRow{
		Kind:        "inventory",
		SchemaVer:   1,
		CollectedAt: time.Date(2026, 10, 24, 10, 0, 0, 0, time.UTC),
		JSON:        `{"inventory_schema_version":1,"hostname":"pc-1"}`,
	}
	h := testAPI(t, fs, &fakeProber{})

	rec := do(h, "GET", "/api/agents/agent:one/inventory", "", bearer)
	if rec.Code != http.StatusOK {
		t.Fatalf("код %d, хочу 200: %s", rec.Code, rec.Body.String())
	}
	want := `"schema_ver":1`
	if !containsStr(rec.Body.String(), want) || !containsStr(rec.Body.String(), `"inventory_schema_version":1`) {
		t.Fatalf("в ответе нет схемы: %s", rec.Body.String())
	}
	if !containsStr(rec.Body.String(), `"hostname":"pc-1"`) {
		t.Fatalf("отчёт исказился: %s", rec.Body.String())
	}

	// Без порций — 404.
	if rec := do(h, "GET", "/api/agents/agent:empty/inventory", "", bearer); rec.Code != http.StatusNotFound {
		t.Fatalf("пустой инвентарь: код %d, хочу 404", rec.Code)
	}
	// Без токена владельца — 401.
	if rec := do(h, "GET", "/api/agents/agent:one/inventory", "", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("без авторизации: код %d, хочу 401", rec.Code)
	}
}

func containsStr(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (haystack == needle ||
		len(needle) == 0 ||
		indexOf(haystack, needle) >= 0)
}

func indexOf(h, n string) int {
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return i
		}
	}
	return -1
}
