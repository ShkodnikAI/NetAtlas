// Активность сотрудников (NR-012): включение с подтверждением
// владельца, приём 5-минутных агрегатов, хранение 90 дней, удаление
// по сроку и по запросу владельца. Сбор по умолчанию выключен; в
// коде нет способа включить его без записи подтверждения.
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

// ActivityRetention — срок хранения данных активности (наряд: 90 дней).
const ActivityRetention = 90 * 24 * time.Hour

// ActivityConfirmationPhrase — фраза подтверждения владельца: без
// точного ввода включение невозможно.
const ActivityConfirmationPhrase = "Сотрудники уведомлены"

// ActivityRow — один 5-минутный агрегат.
type ActivityRow struct {
	AgentID     string         `json:"agent_id"`
	Account     string         `json:"account"`
	WindowStart string         `json:"window_start"`
	ActiveSec   int            `json:"active_sec"`
	IdleSec     int            `json:"idle_sec"`
	Apps        map[string]int `json:"apps"`
	Domains     map[string]int `json:"domains"`
}

// ActivityStatus — состояние сбора для ПК.
type ActivityStatus struct {
	AgentID     string `json:"agent_id"`
	Enabled     bool   `json:"enabled"`
	ConfirmedBy string `json:"confirmed_by,omitempty"`
	ConfirmedAt string `json:"confirmed_at,omitempty"`
}

// EnableActivity — включение сбора для ПК: только с точной фразой
// подтверждения (владелец вводит её в интерфейсе); запись в аудит.
func (s *Store) EnableActivity(ctx context.Context, agentID, phrase, actor string) error {
	if phrase != ActivityConfirmationPhrase {
		return fmt.Errorf("%w: фраза подтверждения не совпадает", ErrScriptValue)
	}
	if actor == "" {
		return fmt.Errorf("%w: актор не задан", ErrScriptValue)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: транзакция включения активности: %w", err)
	}
	defer tx.Rollback()
	var exists int
	if err := tx.QueryRowContext(ctx, `SELECT 1 FROM agents WHERE id = ?`, agentID).Scan(&exists); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return fmt.Errorf("store: агент %s: %w", agentID, err)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, `
                INSERT INTO activity_enabled (agent_id, confirmed_by, confirmed_at, note)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(agent_id) DO UPDATE SET confirmed_by = excluded.confirmed_by,
                                                     confirmed_at = excluded.confirmed_at,
                                                     note = excluded.note`,
		agentID, actor, now, ActivityConfirmationPhrase); err != nil {
		return fmt.Errorf("store: включение активности %s: %w", agentID, err)
	}
	if _, err := audit.Append(ctx, tx, audit.Entry{
		Actor: actor, Action: "activity_enable", Target: agentID, Result: "ok",
		Detail: ActivityConfirmationPhrase, // фиксация подтверждения в аудите
	}); err != nil {
		return err
	}
	return tx.Commit()
}

// DisableActivity — выключение сбора для ПК, запись в аудит.
func (s *Store) DisableActivity(ctx context.Context, agentID, actor string) error {
	if actor == "" {
		return fmt.Errorf("%w: актор не задан", ErrScriptValue)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: транзакция выключения активности: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM activity_enabled WHERE agent_id = ?`, agentID); err != nil {
		return fmt.Errorf("store: выключение активности %s: %w", agentID, err)
	}
	if _, err := audit.Append(ctx, tx, audit.Entry{
		Actor: actor, Action: "activity_disable", Target: agentID, Result: "ok",
	}); err != nil {
		return err
	}
	return tx.Commit()
}

// ActivityEnabled — включён ли сбор для ПК (по умолчанию нет).
func (s *Store) ActivityEnabled(ctx context.Context, agentID string) (bool, error) {
	var exists int
	err := s.db.QueryRowContext(ctx,
		`SELECT 1 FROM activity_enabled WHERE agent_id = ?`, agentID).Scan(&exists)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("store: статус активности %s: %w", agentID, err)
	}
	return true, nil
}

// ListActivityEnabled — все ПК с включённым сбором.
func (s *Store) ListActivityEnabled(ctx context.Context) ([]ActivityStatus, error) {
	rows, err := s.db.QueryContext(ctx, `
                SELECT e.agent_id, e.confirmed_by, e.confirmed_at
                FROM activity_enabled e ORDER BY e.agent_id`)
	if err != nil {
		return nil, fmt.Errorf("store: список включённых: %w", err)
	}
	defer rows.Close()
	out := []ActivityStatus{}
	for rows.Next() {
		var st ActivityStatus
		st.Enabled = true
		if err := rows.Scan(&st.AgentID, &st.ConfirmedBy, &st.ConfirmedAt); err != nil {
			return nil, fmt.Errorf("store: список включённых: строка: %w", err)
		}
		out = append(out, st)
	}
	return out, rows.Err()
}

// SaveActivity — сохранение 5-минутного агрегата. Вызывается только
// после проверки включения (сервер активности). Лимиты: приложение ≤
// 200 имён, домен ≤ 500, счётчики неотрицательные.
func (s *Store) SaveActivity(ctx context.Context, row ActivityRow) error {
	if len(row.Apps) > 200 || len(row.Domains) > 500 {
		return fmt.Errorf("%w: слишком много имён в агрегате", ErrScriptValue)
	}
	apps, err := json.Marshal(row.Apps)
	if err != nil {
		return fmt.Errorf("store: приложения: %w", err)
	}
	domains, err := json.Marshal(row.Domains)
	if err != nil {
		return fmt.Errorf("store: домены: %w", err)
	}
	_, err = s.db.ExecContext(ctx, `
                INSERT INTO activity_reports (agent_id, account, window_start, active_sec, idle_sec, apps, domains, collected_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		row.AgentID, row.Account, row.WindowStart, row.ActiveSec, row.IdleSec,
		string(apps), string(domains), time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		return fmt.Errorf("store: сохранение активности %s: %w", row.AgentID, err)
	}
	return nil
}

// ActivitySummary — агрегации за период.
type ActivitySummary struct {
	From     string            `json:"from"`
	To       string            `json:"to"`
	Totals   map[string]any    `json:"totals"`
	Accounts []ActivityAccount `json:"accounts"`
	Apps     []ActivityNamed   `json:"apps"`
	Domains  []ActivityNamed   `json:"domains"`
}

// ActivityAccount — агрегат по сотруднику.
type ActivityAccount struct {
	Account   string `json:"account"`
	Computer  string `json:"computer"`
	ActiveSec int64  `json:"active_sec"`
	IdleSec   int64  `json:"idle_sec"`
}

// ActivityNamed — агрегат по приложению или домену.
type ActivityNamed struct {
	Name  string `json:"name"`
	Value int64  `json:"value"`
}

// ActivityAggregates — сводка за период [from, to] с фильтрами по
// агенту и учётной записи: суммы, по сотрудникам, приложениям
// (секунды), доменам (запросы), активность по часам.
func (s *Store) ActivityAggregates(ctx context.Context, from, to time.Time, agentID, account string) (ActivitySummary, error) {
	sum := ActivitySummary{
		From: from.UTC().Format(time.RFC3339), To: to.UTC().Format(time.RFC3339),
		Totals: map[string]any{"active_sec": int64(0), "idle_sec": int64(0), "reports": int64(0)},
	}
	var active, idle, reports int64
	if err := s.db.QueryRowContext(ctx, `
                SELECT COALESCE(SUM(active_sec), 0), COALESCE(SUM(idle_sec), 0), COUNT(*)
                FROM activity_reports WHERE collected_at >= ? AND collected_at <= ?`+
		filters(agentID, account), buildArgs(from, to, agentID, account)...).
		Scan(&active, &idle, &reports); err != nil {
		return sum, fmt.Errorf("store: итоги активности: %w", err)
	}
	sum.Totals["active_sec"] = active
	sum.Totals["idle_sec"] = idle
	sum.Totals["reports"] = reports

	// По сотрудникам.
	acctRows, err := s.db.QueryContext(ctx, `
                SELECT account, agent_id, SUM(active_sec), SUM(idle_sec)
                FROM activity_reports WHERE collected_at >= ? AND collected_at <= ?`+
		filters(agentID, account)+` GROUP BY account, agent_id ORDER BY active_sec DESC`,
		buildArgs(from, to, agentID, account)...)
	if err != nil {
		return sum, fmt.Errorf("store: по сотрудникам: %w", err)
	}
	defer acctRows.Close()
	for acctRows.Next() {
		var a ActivityAccount
		if err := acctRows.Scan(&a.Account, &a.Computer, &a.ActiveSec, &a.IdleSec); err != nil {
			return sum, fmt.Errorf("store: по сотрудникам: строка: %w", err)
		}
		sum.Accounts = append(sum.Accounts, a)
	}

	// Приложения: сумма секунд по JSON-ключам — в Go (SQLite без json1 гарантий).
	if sum.Apps, err = s.aggregateJSONMaps(ctx, from, to, agentID, account, "apps"); err != nil {
		return sum, err
	}
	if sum.Domains, err = s.aggregateJSONMaps(ctx, from, to, agentID, account, "domains"); err != nil {
		return sum, err
	}
	return sum, nil
}

// aggregateJSONMaps — свёртка JSON-карт (apps/domains) за период.
func (s *Store) aggregateJSONMaps(ctx context.Context, from, to time.Time, agentID, account, column string) ([]ActivityNamed, error) {
	rows, err := s.db.QueryContext(ctx, `
                SELECT `+column+` FROM activity_reports
                WHERE collected_at >= ? AND collected_at <= ?`+
		filters(agentID, account), buildArgs(from, to, agentID, account)...)
	if err != nil {
		return nil, fmt.Errorf("store: свёртка %s: %w", column, err)
	}
	defer rows.Close()
	total := map[string]int64{}
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, fmt.Errorf("store: свёртка %s: строка: %w", column, err)
		}
		var m map[string]int64
		if json.Unmarshal([]byte(raw), &m) != nil {
			continue // битая строка не роняет сводку
		}
		for k, v := range m {
			total[k] += v
		}
	}
	out := make([]ActivityNamed, 0, len(total))
	for k, v := range total {
		out = append(out, ActivityNamed{Name: k, Value: v})
	}
	// Сортировка по убыванию значения.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j].Value > out[j-1].Value; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	if len(out) > 100 {
		out = out[:100]
	}
	return out, nil
}

// filters — фрагмент SQL по фильтрам (агент, учётная запись).
func filters(agentID, account string) string {
	out := ""
	if agentID != "" {
		out += ` AND agent_id = ?`
	}
	if account != "" {
		out += ` AND account = ?`
	}
	return out
}

// buildArgs — аргументы фильтра периода.
func buildArgs(from, to time.Time, agentID, account string) []any {
	a := []any{from.UTC().Format(time.RFC3339Nano), to.UTC().Format(time.RFC3339Nano)}
	if agentID != "" {
		a = append(a, agentID)
	}
	if account != "" {
		a = append(a, account)
	}
	return a
}

// PurgeOldActivity — удаление старше 90 дней; возвращает число
// удалённых строк (запись в аудит делает вызывающий — серверный
// фоновый цикл раз в сутки).
func (s *Store) PurgeOldActivity(ctx context.Context, now time.Time) (int64, error) {
	cutoff := now.Add(-ActivityRetention).UTC().Format(time.RFC3339Nano)
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM activity_reports WHERE collected_at < ?`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("store: чистка активности: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// DeleteActivityFor — удаление собранного по ПК (запрос владельца),
// запись в аудит.
func (s *Store) DeleteActivityFor(ctx context.Context, agentID, actor string) (int64, error) {
	if actor == "" {
		return 0, fmt.Errorf("%w: актор не задан", ErrScriptValue)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("store: транзакция удаления активности: %w", err)
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `DELETE FROM activity_reports WHERE agent_id = ?`, agentID)
	if err != nil {
		return 0, fmt.Errorf("store: удаление активности %s: %w", agentID, err)
	}
	n, _ := res.RowsAffected()
	detail, _ := json.Marshal(map[string]any{"rows": n})
	if _, err := audit.Append(ctx, tx, audit.Entry{
		Actor: actor, Action: "activity_purge", Target: agentID, Result: "ok", Detail: string(detail),
	}); err != nil {
		return 0, err
	}
	return n, tx.Commit()
}
