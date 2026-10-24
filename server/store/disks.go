// История занятого места по томам (NR-009): дневные точки для
// прогноза заполнения. Пишется при приёме инвентаря, читается
// GET /api/computers и /api/disks.
package store

import (
	"context"
	"fmt"
	"time"
)

// DiskPoint — точка истории одного тома.
type DiskPoint struct {
	Drive    string    `json:"drive"`
	Day      time.Time `json:"day"`
	Used     int64     `json:"used"`
	Capacity int64     `json:"capacity"`
}

// SaveDiskHistory — точки за день из последнего отчёта агента:
// на каждый том INSERT OR REPLACE по ключу (агент, том, день).
// Исключительно локальные данные из инвентаря; ошибки записи не
// роняют приём инвентаря (вызывающий логирует).
func (s *Store) SaveDiskHistory(ctx context.Context, agentID string, points []DiskPoint, now time.Time) error {
	day := now.UTC().Format("2006-01-02")
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: транзакция истории дисков: %w", err)
	}
	defer tx.Rollback()
	for _, p := range points {
		if p.Drive == "" || p.Capacity <= 0 || p.Used < 0 {
			continue
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO disk_history (agent_id, drive, day, used_bytes, capacity_bytes)
			 VALUES (?, ?, ?, ?, ?)
			 ON CONFLICT(agent_id, drive, day) DO UPDATE SET
				used_bytes = excluded.used_bytes,
				capacity_bytes = excluded.capacity_bytes`,
			agentID, p.Drive, day, p.Used, p.Capacity); err != nil {
			return fmt.Errorf("store: точка истории %s/%s: %w", agentID, p.Drive, err)
		}
	}
	return tx.Commit()
}

// DiskHistory — точки тома за последние days дней (для прогноза,
// GET /api/computers и /api/disks).
func (s *Store) DiskHistory(ctx context.Context, agentID, drive string, days int) ([]DiskPoint, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT drive, day, used_bytes, capacity_bytes FROM disk_history
		 WHERE agent_id = ? AND drive = ?
		 ORDER BY day DESC LIMIT ?`, agentID, drive, days)
	if err != nil {
		return nil, fmt.Errorf("store: история дисков %s/%s: %w", agentID, drive, err)
	}
	defer rows.Close()
	out := []DiskPoint{}
	for rows.Next() {
		var p DiskPoint
		var day string
		if err := rows.Scan(&p.Drive, &day, &p.Used, &p.Capacity); err != nil {
			return nil, fmt.Errorf("store: точка истории: %w", err)
		}
		p.Day, err = time.Parse("2006-01-02", day)
		if err != nil {
			return nil, fmt.Errorf("store: дата истории: %w", err)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
