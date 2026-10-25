// Отчёты для ИИ (NR-013): хранение очищенного текста, ответа ИИ и
// таблицы соответствий (отдельная таблица; владельческий маршрут).
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// MaxAnswerBytes — предел ответа ИИ (наряд: 32 КБ).
const MaxAnswerBytes = 32 << 10

// AIReport — отчёт без таблицы соответствий.
type AIReport struct {
	ID          int64  `json:"id"`
	Topic       string `json:"topic"`
	CreatedAt   string `json:"created_at"`
	CleanedText string `json:"cleaned_text"`
	Answer      string `json:"answer,omitempty"`
	Status      string `json:"status"`
}

// MappingRow — одна строка таблицы соответствий.
type MappingRow struct {
	Alias string `json:"alias"`
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

// CreateAIReport — сохранение очищенного отчёта и его таблицы.
func (s *Store) CreateAIReport(ctx context.Context, topic, cleanedText string, mapping []MappingRow) (int64, error) {
	if len(cleanedText) > 512<<10 {
		return 0, fmt.Errorf("%w: отчёт длиннее 512 КБ", ErrScriptValue)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("store: транзакция отчёта: %w", err)
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `
                INSERT INTO ai_reports (topic, created_at, cleaned_text) VALUES (?, ?, ?)`,
		topic, time.Now().UTC().Format(time.RFC3339Nano), cleanedText)
	if err != nil {
		return 0, fmt.Errorf("store: отчёт: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("store: отчёт: id: %w", err)
	}
	for _, m := range mapping {
		if _, err := tx.ExecContext(ctx, `
                        INSERT INTO ai_report_mappings (report_id, alias, kind, value) VALUES (?, ?, ?, ?)`,
			id, m.Alias, m.Kind, m.Value); err != nil {
			return 0, fmt.Errorf("store: соответствие: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("store: фиксация отчёта: %w", err)
	}
	return id, nil
}

// AIReportByID — отчёт; таблица соответствий отдаётся отдельно.
func (s *Store) AIReportByID(ctx context.Context, id int64) (AIReport, error) {
	var r AIReport
	err := s.db.QueryRowContext(ctx, `
                SELECT id, topic, created_at, cleaned_text, answer, status FROM ai_reports WHERE id = ?`, id).
		Scan(&r.ID, &r.Topic, &r.CreatedAt, &r.CleanedText, &r.Answer, &r.Status)
	if errors.Is(err, sql.ErrNoRows) {
		return AIReport{}, ErrNotFound
	}
	if err != nil {
		return AIReport{}, fmt.Errorf("store: отчёт %d: %w", id, err)
	}
	return r, nil
}

// ListAIReports — последние отчёты (без текста).
func (s *Store) ListAIReports(ctx context.Context) ([]AIReport, error) {
	rows, err := s.db.QueryContext(ctx, `
                SELECT id, topic, created_at, status FROM ai_reports ORDER BY id DESC LIMIT 100`)
	if err != nil {
		return nil, fmt.Errorf("store: список отчётов: %w", err)
	}
	defer rows.Close()
	out := []AIReport{}
	for rows.Next() {
		var r AIReport
		if err := rows.Scan(&r.ID, &r.Topic, &r.CreatedAt, &r.Status); err != nil {
			return nil, fmt.Errorf("store: список отчётов: строка: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// SaveAIAnswer — ответ ИИ как текст-предложение.
func (s *Store) SaveAIAnswer(ctx context.Context, id int64, answer string) error {
	if len(answer) > MaxAnswerBytes {
		return fmt.Errorf("%w: ответ длиннее %d байт", ErrScriptValue, MaxAnswerBytes)
	}
	res, err := s.db.ExecContext(ctx, `
                UPDATE ai_reports SET answer = ?, status = 'answered' WHERE id = ?`, answer, id)
	if err != nil {
		return fmt.Errorf("store: ответ: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// AIMapping — таблица соответствий отчёта (только владельцу).
func (s *Store) AIMapping(ctx context.Context, id int64) ([]MappingRow, error) {
	rows, err := s.db.QueryContext(ctx, `
                SELECT alias, kind, value FROM ai_report_mappings WHERE report_id = ? ORDER BY id`, id)
	if err != nil {
		return nil, fmt.Errorf("store: соответствия %d: %w", id, err)
	}
	defer rows.Close()
	out := []MappingRow{}
	for rows.Next() {
		var m MappingRow
		if err := rows.Scan(&m.Alias, &m.Kind, &m.Value); err != nil {
			return nil, fmt.Errorf("store: соответствия %d: строка: %w", id, err)
		}
		out = append(out, m)
	}
	return out, rows.Err()
}
