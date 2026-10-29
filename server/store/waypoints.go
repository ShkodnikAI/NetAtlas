// Точки изгиба связей карты (NR-038 п.1): владелец двойным кликом
// ставит на линии узловую точку, перетаскивает её по мелкой сетке
// 20×20 и удаляет. Точки хранятся на сервере и переживают
// перезагрузку страницы, выход, перезапуск сервера и обновление
// версии; при удалении связи или устройства записи стираются
// (каскад в DeleteManualDevice/DeleteManualLink). Запись идёт в аудит.
package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"unicode"

	"github.com/ShkodnikAI/NetAtlas/server/audit"
)

// WaypointPoint — точка изгиба в модельных координатах карты.
type WaypointPoint struct {
	X float64 `json:"x"`
	Y float64 `json:"y"`
}

// LinkWaypoint — сохранённая точка изгиба: ключ связи, порядковый
// номер на линии (линия проходит точки по порядку), координаты.
type LinkWaypoint struct {
	Link string  `json:"link"`
	Idx  int     `json:"idx"`
	X    float64 `json:"x"`
	Y    float64 `json:"y"`
}

// MaxWaypointsPerLink — ограничение числа точек на одной линии:
// карта изломов длиннее не читается, пакет больше — ошибка клиента.
const MaxWaypointsPerLink = 64

// maxLinkKeyLen — предел длины ключа связи: ключи длиннее — мусор.
const maxLinkKeyLen = 256

// ValidLinkKey — ключ связи непустой, без управляющих символов и не
// длиннее разумного предела. Формат («a|aPort|b|bPort» либо
// «assumed:<id>») сервер не проверяет: ключ приходит с карты, где он
// построен по данным графа.
func ValidLinkKey(key string) error {
	if key == "" {
		return fmt.Errorf("store: ключ связи пустой")
	}
	if len(key) > maxLinkKeyLen {
		return fmt.Errorf("store: ключ связи длиннее %d символов", maxLinkKeyLen)
	}
	for _, r := range key {
		if r > unicode.MaxASCII || unicode.IsControl(r) {
			return fmt.Errorf("store: ключ связи содержит недопустимый символ")
		}
	}
	return nil
}

// wpKeyOf — устойчивый ключ связи из базы (NR-038 п.1): как на карте,
// «a|aPort|b|bPort».
func wpKeyOf(a, aPort, b, bPort string) string {
	return a + "|" + aPort + "|" + b + "|" + bPort
}

// Waypoints — все сохранённые точки изгиба, по ключу связи и порядку
// на линии.
func (s *Store) Waypoints(ctx context.Context) ([]LinkWaypoint, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT link_key, idx, x, y FROM link_waypoints ORDER BY link_key, idx`)
	if err != nil {
		return nil, fmt.Errorf("store: точки изгиба: %w", err)
	}
	defer rows.Close()
	out := []LinkWaypoint{}
	for rows.Next() {
		var p LinkWaypoint
		if err := rows.Scan(&p.Link, &p.Idx, &p.X, &p.Y); err != nil {
			return nil, fmt.Errorf("store: точка изгиба: %w", err)
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: точки изгиба: %w", err)
	}
	return out, nil
}

// SaveWaypoints заменяет все точки изгиба одной связи: клиент после
// каждого изменения (добавление, перетаскивание, удаление, сброс)
// отправляет полный список точек линии; пустой список стирает изгибы.
// Порядок точек — порядок входа: линия проходит их по порядку.
// Координаты — конечные числа: NaN и бесконечности отбрасываются;
// несохранённые точки не меняют соседние индексы (idx присваивается
// заново по выжившим). В аудит — одна запись на запрос.
func (s *Store) SaveWaypoints(ctx context.Context, linkKey string, pts []WaypointPoint, actor string) (int, error) {
	if err := ValidLinkKey(linkKey); err != nil {
		return 0, err
	}
	if len(pts) > MaxWaypointsPerLink {
		return 0, fmt.Errorf("store: точек изгиба %d больше лимита %d", len(pts), MaxWaypointsPerLink)
	}
	kept := make([]WaypointPoint, 0, len(pts))
	for _, p := range pts {
		if checkCoordinate("x", p.X) != nil || checkCoordinate("y", p.Y) != nil {
			continue
		}
		kept = append(kept, p)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("store: транзакция: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM link_waypoints WHERE link_key = ?`, linkKey); err != nil {
		return 0, fmt.Errorf("store: стирание точек связи: %w", err)
	}
	for i, p := range kept {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO link_waypoints (link_key, idx, x, y) VALUES (?, ?, ?, ?)`,
			linkKey, i, p.X, p.Y); err != nil {
			return 0, fmt.Errorf("store: точка изгиба %d связи %s: %w", i, linkKey, err)
		}
	}
	detail, err := jsonDetail(map[string]int{"count": len(kept)})
	if err != nil {
		return 0, err
	}
	if _, err := audit.Append(ctx, tx, audit.Entry{
		Actor: actor, Action: "save_waypoints", Target: linkKey, Result: "ok", Detail: detail,
	}); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("store: фиксация точек изгиба: %w", err)
	}
	return len(kept), nil
}

// ClearWaypoints стирает точки всех связей: «Выстроить сеткой»
// сбрасывает и их (NR-038 п.1). Возвращает число стёртых точек.
func (s *Store) ClearWaypoints(ctx context.Context, actor string) (int, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("store: транзакция: %w", err)
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `DELETE FROM link_waypoints`)
	if err != nil {
		return 0, fmt.Errorf("store: очистка точек изгиба: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("store: очистка точек изгиба: %w", err)
	}
	if _, err := audit.Append(ctx, tx, audit.Entry{
		Actor: actor, Action: "clear_waypoints", Target: "map", Result: "ok",
		Detail: string(mustJSON(map[string]int{"cleared": int(n)})),
	}); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("store: фиксация очистки: %w", err)
	}
	return int(n), nil
}

// deleteWaypointsForDeviceTx — каскад: устройство удалено, его точки
// изгиба стираются. Ключ связи ссылается на устройство, когда это
// «assumed:<id>», либо когда устройство — первый или третий элемент
// ключа «a|aPort|b|bPort» (порты и ключи с другим числом полей не
// совпадают с идентификаторами устройств).
func deleteWaypointsForDeviceTx(ctx context.Context, tx *sql.Tx, deviceID string) error {
	rows, err := tx.QueryContext(ctx, `SELECT DISTINCT link_key FROM link_waypoints`)
	if err != nil {
		return fmt.Errorf("store: точки устройства %s: %w", deviceID, err)
	}
	keys := []string{}
	for rows.Next() {
		var key string
		if err := rows.Scan(&key); err != nil {
			rows.Close()
			return fmt.Errorf("store: точки устройства %s: %w", deviceID, err)
		}
		if linkKeyHasDevice(key, deviceID) {
			keys = append(keys, key)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("store: точки устройства %s: %w", deviceID, err)
	}
	for _, key := range keys {
		if _, err := tx.ExecContext(ctx,
			`DELETE FROM link_waypoints WHERE link_key = ?`, key); err != nil {
			return fmt.Errorf("store: стирание точек связи %s: %w", key, err)
		}
	}
	return nil
}

// linkKeyHasDevice — ссылается ли ключ связи на устройство.
func linkKeyHasDevice(key, deviceID string) bool {
	if key == "assumed:"+deviceID {
		return true
	}
	parts := strings.Split(key, "|")
	return len(parts) == 4 && (parts[0] == deviceID || parts[2] == deviceID)
}

// deleteWaypointsForLinkTx — каскад: связь удалена, её точки изгиба
// стираются в обеих ориентациях ключа (связи в базе хранятся с
// меньшим ID на конце A, но проверяются оба порядка — дешевле, чем
// рассуждать о нормализации).
func deleteWaypointsForLinkTx(ctx context.Context, tx *sql.Tx, a, aPort, b, bPort string) error {
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM link_waypoints WHERE link_key IN (?, ?)`,
		wpKeyOf(a, aPort, b, bPort), wpKeyOf(b, bPort, a, aPort)); err != nil {
		return fmt.Errorf("store: стирание точек связи %s: %w", wpKeyOf(a, aPort, b, bPort), err)
	}
	return nil
}
