// Отчёты безопасности агентов (NR-010): приём конверта проверок,
// хранение истории, выборка последнего отчёта. Изменяющие операции
// пишут аудит в своей транзакции.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/ShkodnikAI/NetAtlas/server/audit"
)

// MaxSecurityResults — предел числа проверок в одном отчёте.
const MaxSecurityResults = 64

// SecurityRow — последняя порция отчёта проверок безопасности.
type SecurityRow struct {
	SchemaVer   int       `json:"schema_ver"`
	CollectedAt time.Time `json:"collected_at"`
	JSON        string    `json:"json"`
}

// SaveSecurity сохраняет отчёт проверок безопасности (тело запроса
// как есть) и пишет аудит. Неизвестный агент — ErrNotFound
// (внешний ключ).
func (s *Store) SaveSecurity(ctx context.Context, agentID string, schemaVer int, collectedAt time.Time, raw []byte) error {
	if collectedAt.IsZero() {
		collectedAt = time.Now()
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: транзакция отчёта безопасности: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO agent_security (agent_id, collected_at, schema_ver, json)
                 VALUES (?, ?, ?, ?)`,
		agentID, collectedAt.UTC().Format(time.RFC3339Nano), schemaVer, string(raw)); err != nil {
		return fmt.Errorf("store: отчёт безопасности %s: %w", agentID, err)
	}
	detail, err := json.Marshal(map[string]any{"agent": agentID, "bytes": len(raw), "schema": schemaVer})
	if err != nil {
		return fmt.Errorf("store: сводка отчёта безопасности: %w", err)
	}
	if _, err := audit.Append(ctx, tx, audit.Entry{
		Actor: agentID, Action: "agent_security", Target: agentID, Result: "ok", Detail: string(detail),
	}); err != nil {
		return err
	}
	return tx.Commit()
}

// LatestSecurity — последний отчёт проверок агента (для сводки
// безопасности). Нет ни агента, ни отчётов — ErrNotFound.
func (s *Store) LatestSecurity(ctx context.Context, agentID string) (SecurityRow, error) {
	var row SecurityRow
	var collected string
	err := s.db.QueryRowContext(ctx,
		`SELECT schema_ver, collected_at, json
                 FROM agent_security WHERE agent_id = ? ORDER BY id DESC LIMIT 1`, agentID).
		Scan(&row.SchemaVer, &collected, &row.JSON)
	if errors.Is(err, sql.ErrNoRows) {
		return SecurityRow{}, ErrNotFound
	}
	if err != nil {
		return SecurityRow{}, fmt.Errorf("store: отчёт безопасности %s: %w", agentID, err)
	}
	row.CollectedAt, err = time.Parse(time.RFC3339Nano, collected)
	if err != nil {
		return SecurityRow{}, fmt.Errorf("store: время отчёта безопасности %s: %w", agentID, err)
	}
	return row, nil
}
