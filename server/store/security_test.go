// Отчёты безопасности в хранилище (NR-010): приём, FK, аудит,
// выборка последнего отчёта.
package store

import (
	"context"
	"testing"
	"time"
)

func TestSaveSecurityAndLatest(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	// Неизвестный агент — FK отклоняет.
	if err := s.SaveSecurity(ctx, "agent:ghost", 1, time.Now(), []byte(`{}`)); err == nil {
		t.Fatal("отчёт неизвестного агента принят")
	}
	if err := s.UpsertAgent(ctx, "agent:sec", "pc1", "1", nil, "owner"); err != nil {
		t.Fatalf("UpsertAgent: %v", err)
	}
	raw := []byte(`{"kind":"security","schema_ver":1,"results":[{"id":"smbv1","status":"fail"}]}`)
	first := time.Date(2026, 10, 24, 10, 0, 0, 0, time.UTC)
	if err := s.SaveSecurity(ctx, "agent:sec", 1, first, raw); err != nil {
		t.Fatalf("SaveSecurity: %v", err)
	}
	// Второй отчёт — новый (история append-only).
	second := time.Date(2026, 10, 24, 11, 0, 0, 0, time.UTC)
	if err := s.SaveSecurity(ctx, "agent:sec", 1, second, []byte(`{"kind":"security","schema_ver":1,"results":[{"id":"smbv1","status":"pass"}]}`)); err != nil {
		t.Fatalf("SaveSecurity 2: %v", err)
	}
	row, err := s.LatestSecurity(ctx, "agent:sec")
	if err != nil {
		t.Fatalf("LatestSecurity: %v", err)
	}
	if row.SchemaVer != 1 {
		t.Fatalf("schema_ver: %d", row.SchemaVer)
	}
	if !row.CollectedAt.Equal(second) && row.CollectedAt.Sub(second) > time.Second {
		t.Fatalf("время последнего отчёта: %v, хочу ~%v", row.CollectedAt, second)
	}
	if len(row.JSON) == 0 {
		t.Fatal("тело отчёта пустое")
	}
	// Аудит: приём записан (две записи — по отчёту).
	entries, err := auditListAll(s)
	if err != nil {
		t.Fatalf("журнал: %v", err)
	}
	found := 0
	for _, e := range entries {
		if e.action == "agent_security" && e.target == "agent:sec" {
			found++
		}
	}
	if found != 2 {
		t.Fatalf("записей аудита agent_security: %d, хочу 2", found)
	}
	// Нет отчётов — ErrNotFound.
	if _, err := s.LatestSecurity(ctx, "agent:ghost"); err != ErrNotFound {
		t.Fatalf("нет отчётов: err %v, хочу ErrNotFound", err)
	}
}
