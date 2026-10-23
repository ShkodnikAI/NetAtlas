package store

import (
	"context"
	"fmt"
	"time"

	"github.com/ShkodnikAI/NetAtlas/server/audit"
)

// RecordVerification фиксирует результат проверки живости устройства:
// при успехе (живости хотя бы одного адреса) выставляет verified=true
// и наблюдение «verify», строка аудита пишется в той же транзакции.
func (s *Store) RecordVerification(ctx context.Context, id, actor string, alive bool, detail string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: транзакция: %w", err)
	}
	defer tx.Rollback()
	var exists int
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM devices WHERE id = ?`, id).Scan(&exists); err != nil {
		return fmt.Errorf("store: устройство %s: %w", id, err)
	}
	if exists == 0 {
		return ErrNotFound
	}
	if alive {
		now := time.Now().UTC().Format(time.RFC3339Nano)
		if _, err := tx.ExecContext(ctx,
			`UPDATE devices SET verified = 1 WHERE id = ?`, id); err != nil {
			return fmt.Errorf("store: признак проверки устройства %s: %w", id, err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO observations (device_id, source, seen)
			VALUES (?, 'verify', ?)
			ON CONFLICT(device_id, source) DO UPDATE SET seen = excluded.seen`,
			id, now); err != nil {
			return fmt.Errorf("store: наблюдение устройства %s: %w", id, err)
		}
	}
	if _, err := audit.Append(ctx, tx, audit.Entry{
		Actor: actor, Action: "verify_device", Target: id, Result: "ok", Detail: detail,
	}); err != nil {
		return err
	}
	return tx.Commit()
}
