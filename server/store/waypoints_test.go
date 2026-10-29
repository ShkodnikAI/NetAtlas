// Тесты хранилища точек изгиба связей (NR-038 п.1): замена точек
// одной связи, порядок и перезапись, отбрасывание мусорных
// координат, лимит, валидация ключа; каскадное стирание при удалении
// ручного устройства и ручной связи; точки переживают переоткрытие
// базы (миграция 18).
package store

import (
	"context"
	"math"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ShkodnikAI/NetAtlas/internal/model"
)

const wpLinkA = "00:00:5e:00:00:01|eth0|00:00:5e:00:00:02|"
const wpLinkAssumed = "assumed:00:00:5e:00:00:02"

// SaveWaypoints пишет и заменяет точки одной связи; мусорные
// координаты отбрасываются; пустой список стирает.
func TestSaveWaypointsReplace(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()

	n, err := s.SaveWaypoints(ctx, wpLinkA, []WaypointPoint{
		{X: 100, Y: 120},
		{X: 140, Y: 120},
	}, "owner")
	if err != nil || n != 2 {
		t.Fatalf("SaveWaypoints: n=%d err=%v, хочу 2/nil", n, err)
	}
	wps, err := s.Waypoints(ctx)
	if err != nil {
		t.Fatalf("Waypoints: %v", err)
	}
	if len(wps) != 2 || wps[0].Link != wpLinkA || wps[0].Idx != 0 || wps[0].X != 100 || wps[1].Idx != 1 {
		t.Fatalf("точки после записи: %+v", wps)
	}

	// Замена: две точки становятся одной; индексы присвоены заново.
	if _, err := s.SaveWaypoints(ctx, wpLinkA, []WaypointPoint{{X: 60, Y: 40}}, "owner"); err != nil {
		t.Fatalf("замена: %v", err)
	}
	wps, _ = s.Waypoints(ctx)
	if len(wps) != 1 || wps[0].Idx != 0 || wps[0].X != 60 || wps[0].Y != 40 {
		t.Fatalf("после замены: %+v, хочу одну точку (60, 40)", wps)
	}

	// Пустой список — сброс изгибов связи.
	if _, err := s.SaveWaypoints(ctx, wpLinkA, nil, "owner"); err != nil {
		t.Fatalf("сброс: %v", err)
	}
	wps, _ = s.Waypoints(ctx)
	if len(wps) != 0 {
		t.Fatalf("после сброса остались точки: %+v", wps)
	}

	// Несколько связей соседствуют: замена одной не трогает другую.
	if _, err := s.SaveWaypoints(ctx, wpLinkA, []WaypointPoint{{X: 1, Y: 2}}, "owner"); err != nil {
		t.Fatalf("связь A: %v", err)
	}
	if _, err := s.SaveWaypoints(ctx, wpLinkAssumed, []WaypointPoint{{X: 3, Y: 4}}, "owner"); err != nil {
		t.Fatalf("связь assumed: %v", err)
	}
	if _, err := s.SaveWaypoints(ctx, wpLinkA, nil, "owner"); err != nil {
		t.Fatalf("сброс A: %v", err)
	}
	wps, _ = s.Waypoints(ctx)
	if len(wps) != 1 || wps[0].Link != wpLinkAssumed {
		t.Fatalf("после сброса A: %+v, хочу только assumed", wps)
	}
}

// Мусор отбрасывается: NaN/бесконечность, кривой ключ, превышение
// лимита.
func TestSaveWaypointsRejectsGarbage(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()

	if _, err := s.SaveWaypoints(ctx, "", []WaypointPoint{{X: 1, Y: 2}}, "owner"); err == nil {
		t.Fatalf("пустой ключ: ошибки нет")
	}
	long := strings.Repeat("x", 300)
	if _, err := s.SaveWaypoints(ctx, long, nil, "owner"); err == nil {
		t.Fatalf("длинный ключ: ошибки нет")
	}
	if _, err := s.SaveWaypoints(ctx, "ключ\nс\tуправляющими", nil, "owner"); err == nil {
		t.Fatalf("управляющие символы: ошибки нет")
	}
	n, err := s.SaveWaypoints(ctx, wpLinkA, []WaypointPoint{
		{X: math.NaN(), Y: 1},
		{X: 1, Y: math.Inf(-1)},
		{X: 1e16, Y: 0},
		{X: 20, Y: 40},
	}, "owner")
	if err != nil || n != 1 {
		t.Fatalf("мусорные координаты: n=%d err=%v, хочу 1/nil", n, err)
	}
	wps, _ := s.Waypoints(ctx)
	if len(wps) != 1 || wps[0].X != 20 {
		t.Fatalf("выжила не та точка: %+v", wps)
	}
	many := make([]WaypointPoint, MaxWaypointsPerLink+1)
	for i := range many {
		many[i] = WaypointPoint{X: float64(i), Y: 0}
	}
	if _, err := s.SaveWaypoints(ctx, wpLinkA, many, "owner"); err == nil {
		t.Fatalf("лимит: ошибки нет")
	}
}

// Каскад: удаление ручного устройства стирает точки его связей,
// включая ключи «assumed:<id>»; удаление ручной связи — точки связи.
func TestWaypointsCascadeOnDelete(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()

	// Ручное устройство + ручная связь к нему.
	id, err := s.AddManualDevice(ctx, model.NodeKindDevice, "ручной", "owner")
	if err != nil {
		t.Fatalf("ручной элемент: %v", err)
	}
	const mac = "00:00:5e:00:00:01"
	res := nr032Scan(t, false)
	if err := s.SaveScan(ctx, res, "test"); err != nil {
		t.Fatalf("SaveScan: %v", err)
	}
	if _, err := s.AddManualLink(ctx, id, "", mac, "", "owner"); err != nil {
		t.Fatalf("ручная связь: %v", err)
	}
	linkKey := id + "||" + mac + "|"
	if mac < id {
		linkKey = mac + "||" + id + "|"
	}
	// Проверка порядка: AddManualLink ставит меньший ID на конец A.
	linkKey, err = s.linkKeyByDevicePair(id, mac)
	if err != nil {
		t.Fatalf("ключ связи: %v", err)
	}
	assumedKey := "assumed:" + id
	for _, key := range []string{linkKey, assumedKey, "ip:10.0.0.1|p|other|q"} {
		if _, err := s.SaveWaypoints(ctx, key, []WaypointPoint{{X: 20, Y: 20}}, "owner"); err != nil {
			t.Fatalf("точки %s: %v", key, err)
		}
	}

	// Удаление ручной связи стирает только её точки.
	linkID, err := s.manualLinkID(linkKey)
	if err != nil {
		t.Fatalf("id связи: %v", err)
	}
	if err := s.DeleteManualLink(ctx, linkID, "owner"); err != nil {
		t.Fatalf("DeleteManualLink: %v", err)
	}
	assertWaypointLinks(t, s, []string{assumedKey, "ip:10.0.0.1|p|other|q"})

	// Удаление устройства стирает и «assumed:<id>», и ключи с ним.
	if err := s.DeleteManualDevice(ctx, id, "owner"); err != nil {
		t.Fatalf("DeleteManualDevice: %v", err)
	}
	assertWaypointLinks(t, s, []string{"ip:10.0.0.1|p|other|q"})
}

// Точки переживают переоткрытие базы: таблица создана миграцией 18,
// данные на месте.
func TestWaypointsSurviveReopen(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "netatlas.db")
	s, err := Open(db)
	if err != nil {
		t.Fatalf("открытие: %v", err)
	}
	if _, err := s.SaveWaypoints(context.Background(), wpLinkA,
		[]WaypointPoint{{X: 40, Y: 60}}, "owner"); err != nil {
		t.Fatalf("запись: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("закрытие: %v", err)
	}
	s2, err := Open(db)
	if err != nil {
		t.Fatalf("переоткрытие: %v", err)
	}
	defer s2.Close()
	wps, err := s2.Waypoints(context.Background())
	if err != nil {
		t.Fatalf("чтение: %v", err)
	}
	if len(wps) != 1 || wps[0].Link != wpLinkA || wps[0].X != 40 || wps[0].Y != 60 {
		t.Fatalf("после переоткрытия: %+v", wps)
	}
}

// ClearWaypoints стирает все точки и возвращает честное число.
func TestClearWaypoints(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	for _, key := range []string{wpLinkA, wpLinkAssumed} {
		if _, err := s.SaveWaypoints(ctx, key, []WaypointPoint{{X: 1, Y: 2}, {X: 3, Y: 4}}, "owner"); err != nil {
			t.Fatalf("запись %s: %v", key, err)
		}
	}
	n, err := s.ClearWaypoints(ctx, "owner")
	if err != nil || n != 4 {
		t.Fatalf("ClearWaypoints: n=%d err=%v, хочу 4/nil", n, err)
	}
	wps, _ := s.Waypoints(ctx)
	if len(wps) != 0 {
		t.Fatalf("после очистки остались точки: %+v", wps)
	}
}

// --- помощники -------------------------------------------------------------

// linkKeyByDevicePair — ключ ручной связи по паре устройств: связь
// ищется в базе, ориентация — как в таблице links.
func (s *Store) linkKeyByDevicePair(a, b string) (string, error) {
	rows, err := s.db.Query(`SELECT a, a_port, b, b_port FROM links WHERE (a = ? AND b = ?) OR (a = ? AND b = ?)`, a, b, b, a)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	for rows.Next() {
		var ka, kaPort, kb, kbPort string
		if err := rows.Scan(&ka, &kaPort, &kb, &kbPort); err != nil {
			return "", err
		}
		return wpKeyOf(ka, kaPort, kb, kbPort), nil
	}
	return "", ErrNotFound
}

// manualLinkID — идентификатор ручной связи по её ключу.
func (s *Store) manualLinkID(key string) (string, error) {
	parts := strings.SplitN(key, "|", 4)
	if len(parts) != 4 {
		return "", ErrNotFound
	}
	var id string
	err := s.db.QueryRow(`SELECT id FROM links WHERE a = ? AND a_port = ? AND b = ? AND b_port = ?`,
		parts[0], parts[1], parts[2], parts[3]).Scan(&id)
	if err != nil {
		return "", ErrNotFound
	}
	return id, nil
}

// assertWaypointLinks — в хранилище остались точки ровно этих связей.
func assertWaypointLinks(t *testing.T, s *Store, want []string) {
	t.Helper()
	wps, err := s.Waypoints(context.Background())
	if err != nil {
		t.Fatalf("Waypoints: %v", err)
	}
	got := map[string]bool{}
	for _, p := range wps {
		got[p.Link] = true
	}
	if len(got) != len(want) {
		t.Fatalf("связей с точками %d, хочу %d: %v", len(got), len(want), got)
	}
	for _, key := range want {
		if !got[key] {
			t.Fatalf("нет точек связи %s, есть %v", key, got)
		}
	}
}
