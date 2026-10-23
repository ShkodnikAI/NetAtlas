package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/ShkodnikAI/NetAtlas/internal/model"
	"github.com/ShkodnikAI/NetAtlas/server/audit"
)

// Alert — оповещение о новом неизвестном устройстве.
type Alert struct {
	ID       int64     `json:"id"`
	DeviceID string    `json:"device_id"`
	Created  time.Time `json:"created"`
	Closed   time.Time `json:"closed"`
	Open     bool      `json:"open"`
}

// AppendAudit пишет строку в журнал аудита вне транзакций данных
// (например, старт сканирования). Изменяющие операции store пишут
// аудит в своей транзакции.
func (s *Store) AppendAudit(ctx context.Context, actor, action, target, detail string) error {
	if _, err := audit.Append(ctx, s.db, audit.Entry{
		Actor: actor, Action: action, Target: target, Result: "ok", Detail: detail,
	}); err != nil {
		return err
	}
	return nil
}

// maybeAlert создаёт оповещение о новом устройстве класса unknown
// внутри транзакции скана: одно открытое на устройство — повторное
// сканирование не создаёт второе (частичный уникальный индекс).
func maybeAlert(ctx context.Context, tx *sql.Tx, deviceID string, isNew bool, now time.Time) error {
	if !isNew {
		return nil
	}
	// Класс проверяется фактом: новое устройство записывается с
	// классом unknown (сканер не классифицирует), но если предыдущая
	// логика сменила класс — оповещение не нужно.
	var class string
	if err := tx.QueryRowContext(ctx,
		`SELECT class FROM devices WHERE id = ?`, deviceID).Scan(&class); err != nil {
		return fmt.Errorf("store: класс устройства %s: %w", deviceID, err)
	}
	if model.Class(class) != model.ClassUnknown {
		return nil
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT OR IGNORE INTO alerts (device_id, created) VALUES (?, ?)`,
		deviceID, now.UTC().Format(time.RFC3339Nano)); err != nil {
		return fmt.Errorf("store: оповещение устройства %s: %w", deviceID, err)
	}
	return nil
}

// closeAlerts закрывает открытые оповещения устройства (смена класса
// владельцем). Возвращает число закрытых.
func closeAlerts(ctx context.Context, tx *sql.Tx, deviceID string, now time.Time) (int64, error) {
	res, err := tx.ExecContext(ctx,
		`UPDATE alerts SET closed = ? WHERE device_id = ? AND closed = ''`,
		now.UTC().Format(time.RFC3339Nano), deviceID)
	if err != nil {
		return 0, fmt.Errorf("store: закрытие оповещений устройства %s: %w", deviceID, err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// ListAlerts возвращает открытые оповещения (новые сверху).
func (s *Store) ListAlerts(ctx context.Context) ([]Alert, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, device_id, created FROM alerts WHERE closed = '' ORDER BY id DESC`)
	if err != nil {
		return nil, fmt.Errorf("store: оповещения: %w", err)
	}
	defer rows.Close()
	out := []Alert{}
	for rows.Next() {
		var a Alert
		var created string
		if err := rows.Scan(&a.ID, &a.DeviceID, &created); err != nil {
			return nil, fmt.Errorf("store: оповещение: %w", err)
		}
		a.Created, err = time.Parse(time.RFC3339Nano, created)
		if err != nil {
			return nil, fmt.Errorf("store: время оповещения: %w", err)
		}
		a.Open = true
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: оповещения: %w", err)
	}
	return out, nil
}

// AckAlert закрывает оповещение по разбору владельцем: не найдено —
// ErrNotFound, уже закрыто — ErrNotManual (конфликт).
func (s *Store) AckAlert(ctx context.Context, id int64, actor string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: транзакция: %w", err)
	}
	defer tx.Rollback()
	var closed string
	err = tx.QueryRowContext(ctx, `SELECT closed FROM alerts WHERE id = ?`, id).Scan(&closed)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("store: оповещение %d: %w", id, err)
	}
	if closed != "" {
		return fmt.Errorf("store: оповещение %d: %w", id, ErrNotManual)
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE alerts SET closed = ? WHERE id = ? AND closed = ''`,
		time.Now().UTC().Format(time.RFC3339Nano), id); err != nil {
		return fmt.Errorf("store: закрытие оповещения %d: %w", id, err)
	}
	detail, _ := json.Marshal(map[string]int64{"id": id})
	if _, err := audit.Append(ctx, tx, audit.Entry{
		Actor: actor, Action: "ack_alert", Target: fmt.Sprintf("alert:%d", id),
		Result: "ok", Detail: string(detail),
	}); err != nil {
		return err
	}
	return tx.Commit()
}
