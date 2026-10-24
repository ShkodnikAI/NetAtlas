// Тест последней порции инвентаря в хранилище (NR-006).
package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

// LatestInventory отдаёт последнюю по id порцию; пусто — ErrNotFound.
func TestLatestInventory(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	if _, err := s.LatestInventory(ctx, "agent:abc"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("у несуществующего агента: %v, хочу ErrNotFound", err)
	}
	if err := s.UpsertAgent(ctx, "agent:abc", "pc1", "1", nil, "owner"); err != nil {
		t.Fatalf("UpsertAgent: %v", err)
	}
	first := []byte(`{"inventory_schema_version":1,"n":1}`)
	second := []byte(`{"inventory_schema_version":1,"n":2}`)
	if err := s.SaveInventory(ctx, "agent:abc", "inventory", 1, time.Now(), first); err != nil {
		t.Fatalf("SaveInventory 1: %v", err)
	}
	if err := s.SaveInventory(ctx, "agent:abc", "inventory", 1, time.Now(), second); err != nil {
		t.Fatalf("SaveInventory 2: %v", err)
	}
	row, err := s.LatestInventory(ctx, "agent:abc")
	if err != nil {
		t.Fatalf("LatestInventory: %v", err)
	}
	if row.JSON != string(second) {
		t.Fatalf("вернулась не последняя порция: %q", row.JSON)
	}
	if row.Kind != "inventory" || row.SchemaVer != 1 {
		t.Fatalf("порция: %+v", row)
	}
	if row.CollectedAt.IsZero() {
		t.Fatal("collected_at пуст")
	}
}
