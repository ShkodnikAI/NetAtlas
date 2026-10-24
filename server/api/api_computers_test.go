// Тесты маршрутов «Компьютеры» и «Диски» (NR-009) и истории томов.
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/ShkodnikAI/NetAtlas/agent/collect"
	"github.com/ShkodnikAI/NetAtlas/rules"
	"github.com/ShkodnikAI/NetAtlas/server/store"
)

// API с подключённым движком правил.
func newRulesAPI(t *testing.T, fs *fakeStore) *API {
	t.Helper()
	re, err := rules.NewEngine("")
	if err != nil {
		t.Fatalf("движок: %v", err)
	}
	a, err := New(fs, token, nil, nil, nil)
	if err != nil {
		t.Fatalf("api: %v", err)
	}
	a.ConfigureRules(re)
	return a
}

func inventoryRow(tb testing.TB, mutate func(*collect.Report)) store.InventoryRow {
	tb.Helper()
	rep := &collect.Report{InventorySchemaVersion: collect.SchemaVersion, Hostname: "pc", CollectedAt: time.Now().UTC().Format(time.RFC3339)}
	if mutate != nil {
		mutate(rep)
	}
	payload, err := json.Marshal(rep)
	if err != nil {
		tb.Fatalf("payload: %v", err)
	}
	env, err := json.Marshal(map[string]any{
		"kind": "inventory", "schema_ver": collect.SchemaVersion,
		"collected_at": time.Now().UTC(), "payload": json.RawMessage(payload),
	})
	if err != nil {
		tb.Fatalf("envelope: %v", err)
	}
	return store.InventoryRow{
		Kind: "inventory", SchemaVer: collect.SchemaVersion,
		CollectedAt: time.Now().UTC(), JSON: string(env),
	}
}

// Без движка правил маршруты отвечают 503.
func TestComputersRulesNotConfigured503(t *testing.T) {
	h := testAPI(t, newFakeStore(), &fakeProber{})
	for _, path := range []string{"/api/computers", "/api/computers/agent:one", "/api/disks"} {
		if rec := do(h, "GET", path, "", bearer); rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s: код %d, хочу 503", path, rec.Code)
		}
	}
}

// Сводка: агент с инвентарём даёт замечания; без инвентаря — нет данных.
func TestComputersSummary(t *testing.T) {
	fs := newFakeStore()
	fs.addAgent("agent:one")
	fs.addAgent("agent:empty")
	fs.inventory["agent:one"] = inventoryRow(t, func(rep *collect.Report) {
		rep.Hardware = &collect.Hardware{TotalPhysicalMemory: "4294967296"} // 4 ГБ
		rep.OS = &collect.OSInfo{Caption: "Microsoft Windows 10 Pro", BuildNumber: "19045"}
	})
	a := newRulesAPI(t, fs)
	rec := do(a.Handler(), "GET", "/api/computers", "", bearer)
	if rec.Code != http.StatusOK {
		t.Fatalf("код %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Computers []computerSummary `json:"computers"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("ответ: %v", err)
	}
	if len(resp.Computers) != 2 {
		t.Fatalf("компьютеров %d, хочу 2", len(resp.Computers))
	}
	var withData, without *computerSummary
	for i := range resp.Computers {
		if resp.Computers[i].ID == "agent:one" {
			withData = &resp.Computers[i]
		} else {
			without = &resp.Computers[i]
		}
	}
	if withData == nil || without == nil {
		t.Fatal("не все компьютеры в ответе")
	}
	// agent:one: 4 ГБ + Windows 10 вне поддержки → warning и critical.
	if withData.Findings["warning"] < 1 || withData.Findings["critical"] < 1 {
		t.Fatalf("замечания: %+v", withData.Findings)
	}
	if withData.MaxPriority < 1000 {
		t.Fatalf("max_priority %v, хочу ≥ 1000 (critical×10)", withData.MaxPriority)
	}
	if withData.InventoryAt == "" {
		t.Fatal("inventory_at пуст")
	}
	if without.InventoryAt != "" || len(without.Findings) != 0 {
		t.Fatalf("агент без данных: %+v", without)
	}
}

// Карточка: инвентарь + замечания + insufficient-прогноз без истории.
func TestComputerCard(t *testing.T) {
	fs := newFakeStore()
	fs.addAgent("agent:one")
	fs.inventory["agent:one"] = inventoryRow(t, func(rep *collect.Report) {
		rep.Disks = &collect.Disks{Volumes: []collect.Volume{
			{DriveLetter: "C", Size: "1000000000000", SizeRemaining: "900000000000"},
		}}
	})
	a := newRulesAPI(t, fs)
	rec := do(a.Handler(), "GET", "/api/computers/agent:one", "", bearer)
	if rec.Code != http.StatusOK {
		t.Fatalf("код %d: %s", rec.Code, rec.Body.String())
	}
	var card computerCard
	if err := json.Unmarshal(rec.Body.Bytes(), &card); err != nil {
		t.Fatalf("ответ: %v", err)
	}
	if card.Inventory == nil || card.Inventory.Hostname != "pc" {
		t.Fatalf("инвентарь: %+v", card.Inventory)
	}
	if card.Forecasts == nil {
		t.Fatal("блок прогнозов отсутствует")
	}
	fc, ok := card.Forecasts["C"]
	if !ok || fc.Insufficient == "" {
		t.Fatalf("без истории должен быть insufficient: %+v", fc)
	}
	if rec := do(a.Handler(), "GET", "/api/computers/agent:ghost", "", bearer); rec.Code != http.StatusNotFound {
		t.Fatalf("чужой: код %d", rec.Code)
	}
}

// Экран «Диски»: тома с заполнением и insufficient-прогнозом.
func TestDisksScreen(t *testing.T) {
	fs := newFakeStore()
	fs.addAgent("agent:one")
	fs.inventory["agent:one"] = inventoryRow(t, func(rep *collect.Report) {
		rep.Disks = &collect.Disks{Volumes: []collect.Volume{
			{DriveLetter: "C", Label: "Система", FileSystem: "NTFS", Size: "1000000000000", SizeRemaining: "200000000000"},
			{DriveLetter: "D", Size: "2000000000000", SizeRemaining: "1000000000000"},
		}}
	})
	a := newRulesAPI(t, fs)
	rec := do(a.Handler(), "GET", "/api/disks", "", bearer)
	if rec.Code != http.StatusOK {
		t.Fatalf("код %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Disks []diskView `json:"disks"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("ответ: %v", err)
	}
	if len(resp.Disks) != 2 {
		t.Fatalf("томов %d, хочу 2", len(resp.Disks))
	}
	if resp.Disks[0].Drive != "C" || resp.Disks[0].FreePct < 19 || resp.Disks[0].FreePct > 21 {
		t.Fatalf("том C: %+v", resp.Disks[0])
	}
	if resp.Disks[0].Forecast.Insufficient == "" {
		t.Fatal("без истории прогноз должен быть insufficient")
	}
	if !containsSubstr(rec.Body.String(), `"hostname":"pc"`) {
		t.Fatal("в ответе нет хоста")
	}
}

func containsSubstr(h, n string) bool {
	return len(h) >= len(n) && (index(h, n) >= 0)
}

func index(h, n string) int {
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return i
		}
	}
	return -1
}

// История дисков в хранилище: upsert за день и чтение (настоящий store).
func TestDiskHistoryStore(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "netatlas.db"))
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	defer st.Close()
	ctx := context.Background()
	now := time.Date(2026, 10, 24, 10, 0, 0, 0, time.UTC)
	points := []store.DiskPoint{
		{Drive: "C", Used: 100, Capacity: 1000},
		{Drive: "D", Used: 200, Capacity: 2000},
	}
	if err := st.SaveDiskHistory(ctx, "agent:a", points, now); err != nil {
		t.Fatalf("SaveDiskHistory: %v", err)
	}
	// Повтор за тот же день: замещает (последний отчёт побеждает).
	points[0].Used = 150
	if err := st.SaveDiskHistory(ctx, "agent:a", points, now); err != nil {
		t.Fatalf("SaveDiskHistory 2: %v", err)
	}
	got, err := st.DiskHistory(ctx, "agent:a", "C", 30)
	if err != nil {
		t.Fatalf("DiskHistory: %v", err)
	}
	if len(got) != 1 || got[0].Used != 150 || got[0].Capacity != 1000 {
		t.Fatalf("точки: %+v", got)
	}
	// Другой том не задет.
	gotD, err := st.DiskHistory(ctx, "agent:a", "D", 30)
	if err != nil || len(gotD) != 1 || gotD[0].Used != 200 {
		t.Fatalf("том D: %+v (err %v)", gotD, err)
	}
}
