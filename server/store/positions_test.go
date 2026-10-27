// Тесты хранилища позиций NR-035 п.1: пакетная запись SavePositions —
// вставка, обновление, пропуск несуществующих узлов и мусорных
// координат; позиции переживают переоткрытие базы.
package store

import (
	"context"
	"math"
	"path/filepath"
	"testing"
)

// SavePositions записывает пакет: существующие узлы сохраняются,
// несуществующие и мусорные координаты пропускаются, ответ честно
// называет число записанных позиций.
func TestSavePositionsBatch(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	res := nr032Scan(t, false)
	if err := s.SaveScan(ctx, res, "test"); err != nil {
		t.Fatalf("SaveScan: %v", err)
	}
	pc := "00:00:5e:00:00:01"
	printer := "00:80:77:00:00:01"

	saved, err := s.SavePositions(ctx, []NodePosition{
		{ID: pc, X: 100, Y: 120},
		{ID: printer, X: 200, Y: 240},
		{ID: "manual:нет-такого", X: 1, Y: 2}, // несуществующий — пропуск
		{ID: pc, X: math.NaN(), Y: 5},         // NaN — пропуск
		{ID: pc, X: math.Inf(1), Y: 5},        // бесконечность — пропуск
		{ID: pc, X: 300, Y: 360},              // повтор: перезапись первой
	}, "owner")
	if err != nil {
		t.Fatalf("SavePositions: %v", err)
	}
	if saved != 3 {
		t.Fatalf("записано %d позиций, хочу 3 (повтор узла тоже запись)", saved)
	}
	positions, err := s.Positions(ctx)
	if err != nil {
		t.Fatalf("Positions: %v", err)
	}
	if len(positions) != 2 {
		t.Fatalf("в хранилище %d позиций, хочу 2", len(positions))
	}
	byID := map[string]NodePosition{}
	for _, p := range positions {
		byID[p.ID] = p
	}
	if got := byID[pc]; got.X != 300 || got.Y != 360 {
		t.Fatalf("позиция %s = %+v, хочу перезаписанную (300, 360)", pc, got)
	}
	if got := byID[printer]; got.X != 200 || got.Y != 240 {
		t.Fatalf("позиция %s = %+v, хочу (200, 240)", printer, got)
	}

	// Пустой пакет — не ошибка, ничего не пишется и в аудит не идёт.
	saved, err = s.SavePositions(ctx, nil, "owner")
	if err != nil || saved != 0 {
		t.Fatalf("пустой пакет: saved=%d, err=%v", saved, err)
	}
}

// Позиции переживают переоткрытие базы (перезапуск сервера и
// обновление версии, NR-035 п.1).
func TestPositionsSurviveReopen(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "map.db")
	s, err := Open(db)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	ctx := context.Background()
	res := nr032Scan(t, false)
	if err := s.SaveScan(ctx, res, "test"); err != nil {
		t.Fatalf("SaveScan: %v", err)
	}
	pc := "00:00:5e:00:00:01"
	if _, err := s.SavePositions(ctx, []NodePosition{{ID: pc, X: -120, Y: 480}}, "owner"); err != nil {
		t.Fatalf("SavePositions: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	s2, err := Open(db)
	if err != nil {
		t.Fatalf("переоткрытие: %v", err)
	}
	defer s2.Close()
	positions, err := s2.Positions(ctx)
	if err != nil {
		t.Fatalf("Positions после переоткрытия: %v", err)
	}
	if len(positions) != 1 || positions[0].ID != pc || positions[0].X != -120 || positions[0].Y != 480 {
		t.Fatalf("позиции после переоткрытия = %+v, хочу одну (%s: -120, 480)", positions, pc)
	}
}

// Пакетная запись в аудит пишется одной записью на пакет: цепочка
// остаётся целой, запись одна.
func TestSavePositionsAuditOnce(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	if err := s.SaveScan(ctx, nr032Scan(t, false), "test"); err != nil {
		t.Fatalf("SaveScan: %v", err)
	}
	pc, printer := "00:00:5e:00:00:01", "00:80:77:00:00:01"
	if _, err := s.SavePositions(ctx, []NodePosition{{ID: pc, X: 1, Y: 2}, {ID: printer, X: 3, Y: 4}}, "owner"); err != nil {
		t.Fatalf("SavePositions: %v", err)
	}
	entries, err := s.AuditForTarget(ctx, "map", 50)
	if err != nil {
		t.Fatalf("AuditForTarget: %v", err)
	}
	count := 0
	for _, e := range entries {
		if e.Action == "save_positions" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("записей save_positions в аудите %d, хочу 1", count)
	}
}
