package store

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/ShkodnikAI/NetAtlas/server/audit"
)

// NodePosition — позиция узла на карте, сдвинутая владельцем
// (NR-032 п.4): детерминированная раскладка такие позиции не трогает.
type NodePosition struct {
	ID string  `json:"id"`
	X  float64 `json:"x"`
	Y  float64 `json:"y"`
}

// SavePosition запоминает позицию узла: узел должен существовать,
// координаты — конечные числа (проверка вызывающего не отменяется:
// NaN и бесконечности отбрасываются здесь). Пишется в аудит.
func (s *Store) SavePosition(ctx context.Context, id string, x, y float64, actor string) error {
	if err := checkCoordinate("x", x); err != nil {
		return err
	}
	if err := checkCoordinate("y", y); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: транзакция: %w", err)
	}
	defer tx.Rollback()
	var exists int
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM devices WHERE id = ?`, id).Scan(&exists); err != nil {
		return fmt.Errorf("store: узел %s: %w", id, err)
	}
	if exists == 0 {
		return fmt.Errorf("store: узел %s: %w", id, ErrNotFound)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO node_positions (node_id, x, y, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(node_id) DO UPDATE SET x = excluded.x, y = excluded.y, updated_at = excluded.updated_at`,
		id, x, y, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		return fmt.Errorf("store: позиция узла %s: %w", id, err)
	}
	detail, err := jsonDetail(map[string]float64{"x": x, "y": y})
	if err != nil {
		return err
	}
	if _, err := audit.Append(ctx, tx, audit.Entry{
		Actor: actor, Action: "save_position", Target: id, Result: "ok", Detail: detail,
	}); err != nil {
		return err
	}
	return tx.Commit()
}

// Positions — все запомненные позиции узлов, по возрастанию ID.
func (s *Store) Positions(ctx context.Context) ([]NodePosition, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT node_id, x, y FROM node_positions ORDER BY node_id`)
	if err != nil {
		return nil, fmt.Errorf("store: позиции: %w", err)
	}
	defer rows.Close()
	out := []NodePosition{}
	for rows.Next() {
		var p NodePosition
		if err := rows.Scan(&p.ID, &p.X, &p.Y); err != nil {
			return nil, fmt.Errorf("store: позиция: %w", err)
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: позиции: %w", err)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// ClearPositions стирает все запомненные позиции: детерминированная
// раскладка заново выстраивает карту сеткой. Пишется в аудит.
func (s *Store) ClearPositions(ctx context.Context, actor string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: транзакция: %w", err)
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `DELETE FROM node_positions`)
	if err != nil {
		return fmt.Errorf("store: очистка позиций: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: очистка позиций: %w", err)
	}
	if _, err := audit.Append(ctx, tx, audit.Entry{
		Actor: actor, Action: "clear_positions", Target: "map", Result: "ok",
		Detail: string(mustJSON(map[string]int{"cleared": int(n)})),
	}); err != nil {
		return err
	}
	return tx.Commit()
}

// SavePositions запоминает позиции пакетом (NR-035 п.1): клиент
// отправляет все сдвинутые узлы одним запросом после дебаунса.
// Пакет пишется одной транзакцией; несуществующие узлы пропускаются
// (устройство могло быть удалено между загрузкой карты и сохранением),
// координаты — конечные числа: NaN и бесконечности отбрасываются.
// Возвращает число записанных позиций. В аудит — одна запись на пакет.
func (s *Store) SavePositions(ctx context.Context, pos []NodePosition, actor string) (int, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("store: транзакция: %w", err)
	}
	defer tx.Rollback()
	saved := 0
	for _, p := range pos {
		if err := checkCoordinate("x", p.X); err != nil {
			continue
		}
		if err := checkCoordinate("y", p.Y); err != nil {
			continue
		}
		var exists int
		if err := tx.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM devices WHERE id = ?`, p.ID).Scan(&exists); err != nil {
			return 0, fmt.Errorf("store: узел %s: %w", p.ID, err)
		}
		if exists == 0 {
			continue
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO node_positions (node_id, x, y, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(node_id) DO UPDATE SET x = excluded.x, y = excluded.y, updated_at = excluded.updated_at`,
			p.ID, p.X, p.Y, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
			return 0, fmt.Errorf("store: позиция узла %s: %w", p.ID, err)
		}
		saved++
	}
	if saved > 0 {
		detail, err := jsonDetail(map[string]int{"count": saved})
		if err != nil {
			return 0, err
		}
		if _, err := audit.Append(ctx, tx, audit.Entry{
			Actor: actor, Action: "save_positions", Target: "map", Result: "ok", Detail: detail,
		}); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("store: фиксация позиций: %w", err)
	}
	return saved, nil
}

// checkCoordinate — координата должна быть конечным числом: NaN и
// бесконечности ломают раскладку и JSON.
func checkCoordinate(name string, v float64) error {
	if v != v || v > 1e15 || v < -1e15 {
		return fmt.Errorf("store: координата %s = %v: недопустимое значение", name, v)
	}
	return nil
}
