// Задания и цели (NR-011): создание задания владельцем, состояния по
// агентам, приём результатов с автостановкой при первой ошибке или
// ухудшении метрики, выдача в checkin (кандидаты для шлюза pipeline/
// gate). Выдача и смена статусов идут через gate; очередь для
// выключенных машин — состояние queued до следующего checkin.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ShkodnikAI/NetAtlas/pipeline/catalog"
	"github.com/ShkodnikAI/NetAtlas/pipeline/gate"
	"github.com/ShkodnikAI/NetAtlas/server/audit"
)

// MaxJobTargets — предел числа целей одного задания.
const MaxJobTargets = 500

// JobTargetRow — состояние задания по одному агенту.
type JobTargetRow struct {
	AgentID      string   `json:"agent_id"`
	State        string   `json:"state"`
	Result       string   `json:"result,omitempty"`
	Error        string   `json:"error,omitempty"`
	SentAt       string   `json:"sent_at,omitempty"`
	UpdatedAt    string   `json:"updated_at"`
	MetricBefore *float64 `json:"metric_before,omitempty"`
	MetricAfter  *float64 `json:"metric_after,omitempty"`
}

// JobRow — задание с целями.
type JobRow struct {
	ID              int64          `json:"id"`
	ScriptVersionID int64          `json:"script_version_id"`
	ScriptID        int64          `json:"script_id"`
	Name            string         `json:"name"`
	Kind            string         `json:"kind"`
	Status          string         `json:"status"`
	Pilot           bool           `json:"pilot"`
	WindowStart     string         `json:"window_start,omitempty"`
	WindowEnd       string         `json:"window_end,omitempty"`
	Deadline        string         `json:"deadline,omitempty"`
	MetricThreshold float64        `json:"metric_threshold"`
	CreatedAt       string         `json:"created_at"`
	CreatedBy       string         `json:"created_by"`
	Targets         []JobTargetRow `json:"targets"`
}

// CreateJobInput — вход создания задания.
type CreateJobInput struct {
	ScriptVersionID int64
	Targets         []string
	Pilot           bool
	WindowStart     string
	WindowEnd       string
	Deadline        string
	MetricThreshold float64
}

// CreateJob — создание задания: только на подписанную версию
// (статус не ниже signed, подпись покрывает хэш версии), цели —
// существующие агенты, пилот — ровно один ПК. Диспетчеризация
// (отдача агентам) здесь не решается: её шлюз проверяет в checkin.
func (s *Store) CreateJob(ctx context.Context, in CreateJobInput, actor string) (int64, error) {
	if actor == "" {
		return 0, fmt.Errorf("%w: актор не задан", ErrScriptValue)
	}
	if len(in.Targets) == 0 {
		return 0, fmt.Errorf("%w: задание без целей", ErrScriptValue)
	}
	if len(in.Targets) > MaxJobTargets {
		return 0, fmt.Errorf("%w: целей больше %d", ErrScriptValue, MaxJobTargets)
	}
	if in.Pilot && len(in.Targets) != 1 {
		return 0, fmt.Errorf("%w: пилотное задание — ровно один ПК", ErrScriptValue)
	}
	seen := map[string]bool{}
	for _, t := range in.Targets {
		if t == "" || seen[t] {
			return 0, fmt.Errorf("%w: пустая или повторная цель", ErrScriptValue)
		}
		seen[t] = true
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("store: транзакция задания: %w", err)
	}
	defer tx.Rollback()
	var vID, scriptID int64
	var vStatus, vSHA, name, kind string
	err = tx.QueryRowContext(ctx, `
                SELECT v.id, v.script_id, v.status, v.sha256, s.name, s.kind
                FROM script_versions v JOIN scripts s ON s.id = v.script_id
                WHERE v.id = ?`, in.ScriptVersionID).
		Scan(&vID, &scriptID, &vStatus, &vSHA, &name, &kind)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrNotFound
	}
	if err != nil {
		return 0, fmt.Errorf("store: версия %d: %w", in.ScriptVersionID, err)
	}
	if !gate.AtLeast(vStatus, gate.StatusSigned) {
		return 0, fmt.Errorf("%w: задание создаётся на подписанную версию (статус %q)", ErrScriptState, vStatus)
	}
	sig, err := latestSignatureTx(ctx, tx, vID)
	if err != nil {
		return 0, err
	}
	if sig.SHA256 != vSHA {
		return 0, fmt.Errorf("%w: подпись не покрывает содержимое версии", ErrScriptState)
	}
	for _, t := range in.Targets {
		var exists int
		if err := tx.QueryRowContext(ctx, `SELECT 1 FROM agents WHERE id = ?`, t).Scan(&exists); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return 0, fmt.Errorf("%w: агент %s не зарегистрирован", ErrNotFound, t)
			}
			return 0, fmt.Errorf("store: агент %s: %w", t, err)
		}
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	res, err := tx.ExecContext(ctx, `
                INSERT INTO jobs (script_version_id, name, kind, status, pilot, window_start, window_end,
                                  deadline, metric_threshold, created_at, created_by)
                VALUES (?, ?, ?, 'pending', ?, ?, ?, ?, ?, ?, ?)`,
		vID, name, kind, boolInt(in.Pilot), in.WindowStart, in.WindowEnd,
		in.Deadline, in.MetricThreshold, now, actor)
	if err != nil {
		return 0, fmt.Errorf("store: задание: %w", err)
	}
	jobID, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("store: задание: id: %w", err)
	}
	for _, t := range in.Targets {
		if _, err := tx.ExecContext(ctx, `
                        INSERT INTO job_targets (job_id, agent_id, state, updated_at)
                        VALUES (?, ?, 'queued', ?)`, jobID, t, now); err != nil {
			return 0, fmt.Errorf("store: цель %s: %w", t, err)
		}
	}
	detail, err := json.Marshal(map[string]any{
		"job": jobID, "version": vID, "targets": len(in.Targets), "pilot": in.Pilot,
	})
	if err != nil {
		return 0, fmt.Errorf("store: сводка задания: %w", err)
	}
	if _, err := audit.Append(ctx, tx, audit.Entry{
		Actor: actor, Action: "job_create", Target: name, Result: "ok", Detail: string(detail),
	}); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("store: фиксация задания: %w", err)
	}
	return jobID, nil
}

// StopJob — остановка задания владельцем: queued-цели снимаются.
func (s *Store) StopJob(ctx context.Context, jobID int64, reason, actor string) error {
	if actor == "" {
		return fmt.Errorf("%w: актор не задан", ErrScriptValue)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: транзакция остановки: %w", err)
	}
	defer tx.Rollback()
	var name, status string
	err = tx.QueryRowContext(ctx, `SELECT name, status FROM jobs WHERE id = ?`, jobID).Scan(&name, &status)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("store: задание %d: %w", jobID, err)
	}
	if status == "done" || status == "stopped" {
		return fmt.Errorf("%w: задание уже %s", ErrScriptState, status)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, `UPDATE jobs SET status = 'stopped' WHERE id = ?`, jobID); err != nil {
		return fmt.Errorf("store: задание %d: статус: %w", jobID, err)
	}
	if _, err := tx.ExecContext(ctx, `
                UPDATE job_targets SET state = 'stopped', updated_at = ?
                WHERE job_id = ? AND state = 'queued'`, now, jobID); err != nil {
		return fmt.Errorf("store: задание %d: снятие целей: %w", jobID, err)
	}
	detail, err := json.Marshal(map[string]any{"job": jobID, "reason": reason})
	if err != nil {
		return fmt.Errorf("store: сводка остановки: %w", err)
	}
	if _, err := audit.Append(ctx, tx, audit.Entry{
		Actor: actor, Action: "job_stop", Target: name, Result: "ok", Detail: string(detail),
	}); err != nil {
		return err
	}
	return tx.Commit()
}

// ListJobs — задания (все или по версии), с целями.
func (s *Store) ListJobs(ctx context.Context, versionID int64) ([]JobRow, error) {
	q := `SELECT j.id, j.script_version_id, v.script_id, j.name, j.kind, j.status, j.pilot,
                     j.window_start, j.window_end, j.deadline, j.metric_threshold, j.created_at, j.created_by
              FROM jobs j JOIN script_versions v ON v.id = j.script_version_id`
	var args []any
	if versionID > 0 {
		q += ` WHERE j.script_version_id = ?`
		args = append(args, versionID)
	}
	q += ` ORDER BY j.id DESC LIMIT 200`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("store: список заданий: %w", err)
	}
	defer rows.Close()
	jobs := []JobRow{}
	for rows.Next() {
		var j JobRow
		var pilot int
		if err := rows.Scan(&j.ID, &j.ScriptVersionID, &j.ScriptID, &j.Name, &j.Kind, &j.Status, &pilot,
			&j.WindowStart, &j.WindowEnd, &j.Deadline, &j.MetricThreshold, &j.CreatedAt, &j.CreatedBy); err != nil {
			return nil, fmt.Errorf("store: список заданий: строка: %w", err)
		}
		j.Pilot = pilot == 1
		j.Targets = []JobTargetRow{}
		jobs = append(jobs, j)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: список заданий: %w", err)
	}
	for i := range jobs {
		targets, err := s.jobTargets(ctx, jobs[i].ID)
		if err != nil {
			return nil, err
		}
		jobs[i].Targets = targets
	}
	return jobs, nil
}

// JobByID — задание с целями; нет задания — ErrNotFound.
func (s *Store) JobByID(ctx context.Context, jobID int64) (JobRow, error) {
	var j JobRow
	var pilot int
	err := s.db.QueryRowContext(ctx, `
                SELECT j.id, j.script_version_id, v.script_id, j.name, j.kind, j.status, j.pilot,
                       j.window_start, j.window_end, j.deadline, j.metric_threshold, j.created_at, j.created_by
                FROM jobs j JOIN script_versions v ON v.id = j.script_version_id
                WHERE j.id = ?`, jobID).
		Scan(&j.ID, &j.ScriptVersionID, &j.ScriptID, &j.Name, &j.Kind, &j.Status, &pilot,
			&j.WindowStart, &j.WindowEnd, &j.Deadline, &j.MetricThreshold, &j.CreatedAt, &j.CreatedBy)
	if errors.Is(err, sql.ErrNoRows) {
		return JobRow{}, ErrNotFound
	}
	if err != nil {
		return JobRow{}, fmt.Errorf("store: задание %d: %w", jobID, err)
	}
	j.Pilot = pilot == 1
	j.Targets, err = s.jobTargets(ctx, jobID)
	return j, err
}

// RecordJobResult — приём результата от агента: цель sent → done
// или failed. При провале — автоматическая остановка раскатки
// (задание stopped, остальные queued снимаются), при ухудшении
// метрики «до/после» сверх порога — та же остановка с причиной.
// Успех пилотного задания отмечает pilot_ok у версии.
func (s *Store) RecordJobResult(ctx context.Context, jobID int64, agentID string, ok bool, detail string, before, after *float64, actor string) (JobTargetRow, error) {
	if actor == "" {
		return JobTargetRow{}, fmt.Errorf("%w: актор не задан", ErrScriptValue)
	}
	if len(detail) > MaxScriptDetailLen {
		detail = detail[:MaxScriptDetailLen]
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return JobTargetRow{}, fmt.Errorf("store: транзакция результата: %w", err)
	}
	defer tx.Rollback()
	var jName, jStatus string
	var threshold float64
	var jPilot int
	err = tx.QueryRowContext(ctx,
		`SELECT name, status, metric_threshold, pilot FROM jobs WHERE id = ?`, jobID).
		Scan(&jName, &jStatus, &threshold, &jPilot)
	if errors.Is(err, sql.ErrNoRows) {
		return JobTargetRow{}, ErrNotFound
	}
	if err != nil {
		return JobTargetRow{}, fmt.Errorf("store: задание %d: %w", jobID, err)
	}
	var state string
	err = tx.QueryRowContext(ctx,
		`SELECT state FROM job_targets WHERE job_id = ? AND agent_id = ?`, jobID, agentID).Scan(&state)
	if errors.Is(err, sql.ErrNoRows) {
		return JobTargetRow{}, ErrNotFound
	}
	if err != nil {
		return JobTargetRow{}, fmt.Errorf("store: цель %s: %w", agentID, err)
	}
	if state != "sent" {
		return JobTargetRow{}, fmt.Errorf("%w: цель %s в состоянии %q, результат не ждётся", ErrScriptState, agentID, state)
	}

	// Метрика «до/после»: ухудшение сверх порога — провал с причиной.
	reason := ""
	if ok && threshold > 0 && before != nil && after != nil && *after-*before > threshold {
		ok = false
		reason = fmt.Sprintf("метрика ухудшилась: было %.2f, стало %.2f, порог %.2f", *before, *after, threshold)
	}

	newState := "failed"
	result := "fail"
	if ok {
		newState, result = "done", "ok"
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, `
                UPDATE job_targets SET state = ?, result = ?, error = ?, metric_before = ?, metric_after = ?, updated_at = ?
                WHERE job_id = ? AND agent_id = ?`,
		newState, result, reason, before, after, now, jobID, agentID); err != nil {
		return JobTargetRow{}, fmt.Errorf("store: цель %s: результат: %w", agentID, err)
	}
	target := JobTargetRow{AgentID: agentID, State: newState, Result: result, Error: reason,
		MetricBefore: before, MetricAfter: after, UpdatedAt: now}

	// Автостановка при первой ошибке.
	if !ok {
		if _, err := tx.ExecContext(ctx,
			`UPDATE jobs SET status = 'stopped' WHERE id = ? AND status IN ('pending','running')`, jobID); err != nil {
			return JobTargetRow{}, fmt.Errorf("store: задание %d: остановка: %w", jobID, err)
		}
		if _, err := tx.ExecContext(ctx, `
                        UPDATE job_targets SET state = 'stopped', updated_at = ?
                        WHERE job_id = ? AND state = 'queued'`, now, jobID); err != nil {
			return JobTargetRow{}, fmt.Errorf("store: задание %d: снятие очереди: %w", jobID, err)
		}
		detail, err := json.Marshal(map[string]any{
			"job": jobID, "agent": agentID, "reason": reason, "detail": detail,
		})
		if err != nil {
			return JobTargetRow{}, fmt.Errorf("store: сводка автостопа: %w", err)
		}
		if _, err := audit.Append(ctx, tx, audit.Entry{
			Actor: actor, Action: "job_autostop", Target: jName, Result: "fail", Detail: string(detail),
		}); err != nil {
			return JobTargetRow{}, err
		}
	}

	// Успех пилотного задания отмечает пройденный пилот у версии.
	if ok && jPilot == 1 {
		if _, err := tx.ExecContext(ctx, `
                        UPDATE script_versions SET pilot_ok = 1
                        WHERE id = (SELECT script_version_id FROM jobs WHERE id = ?)`, jobID); err != nil {
			return JobTargetRow{}, fmt.Errorf("store: пилот версии: %w", err)
		}
	}
	detailFull, err := json.Marshal(map[string]any{
		"job": jobID, "agent": agentID, "state": newState, "detail": detail,
	})
	if err != nil {
		return JobTargetRow{}, fmt.Errorf("store: сводка результата: %w", err)
	}
	if _, err := audit.Append(ctx, tx, audit.Entry{
		Actor: actor, Action: "job_result", Target: jName, Result: result, Detail: string(detailFull),
	}); err != nil {
		return JobTargetRow{}, err
	}
	if err := tx.Commit(); err != nil {
		return JobTargetRow{}, fmt.Errorf("store: фиксация результата: %w", err)
	}
	return target, nil
}

// DispatchCandidate — кандидат на выдачу в checkin: всё, что
// требуется шлюзу gate.CanDispatch и подписанию конверта.
type DispatchCandidate struct {
	JobID     int64  `json:"job_id"`
	JobName   string `json:"job_name"`
	Kind      string `json:"kind"`
	Content   string `json:"content"`
	VersionID int64  `json:"version_id"`
	Version   int64  `json:"version"`
	// Поля для gate.Script:
	Status    string    `json:"status"`
	Category  string    `json:"category"`
	SHA256    string    `json:"sha256"`
	SignedBy  string    `json:"signed_by"`
	SignedSHA string    `json:"signed_sha"`
	Expires   time.Time `json:"-"`
	PilotOK   bool      `json:"pilot_ok"`
	// Разрешённый набор целей задания (для gate.Job.Targets).
	Targets []string `json:"targets"`
	// IsPilot — задание этапа «один ПК» (pilot).
	IsPilot bool `json:"is_pilot"`
	// CatalogKey — ключ шаблона для kind=catalog (изменяющий флаг
	// агенту вычисляется на сервере из шаблона).
	CatalogKey string `json:"catalog_key,omitempty"`
	// ChangesSystem — задание изменяет состояние машины: каталог из
	// шаблона не только-чтение; произвольный скрипт — всегда.
	ChangesSystem bool `json:"changes_system"`
	// Состояние раскатки:
	Total     int `json:"total"`
	Done      int `json:"done"`
	Delivered int `json:"delivered"`
}

// PendingDispatch — queued-цели агента по живым заданиям с данными
// для шлюза и квоты раскатки. Порядок — старые задания вперёд.
func (s *Store) PendingDispatch(ctx context.Context, agentID string) ([]DispatchCandidate, error) {
	rows, err := s.db.QueryContext(ctx, `
                SELECT j.id, j.name, j.kind, j.pilot,
                       v.id, v.version, v.status, v.content, v.sha256, v.pilot_ok, s.category, s.catalog_key, s.kind,
                       COALESCE(sig.signed_by, ''), COALESCE(sig.sha256, ''), COALESCE(sig.expires_at, ''),
                       (SELECT COUNT(*) FROM job_targets WHERE job_id = j.id),
                       (SELECT COUNT(*) FROM job_targets WHERE job_id = j.id AND state = 'done'),
                       (SELECT COUNT(*) FROM job_targets WHERE job_id = j.id AND state != 'queued'),
                       (SELECT COALESCE(GROUP_CONCAT(agent_id, ','), '') FROM job_targets WHERE job_id = j.id)
                FROM job_targets jt
                JOIN jobs j ON j.id = jt.job_id
                JOIN script_versions v ON v.id = j.script_version_id
                JOIN scripts s ON s.id = v.script_id
                LEFT JOIN signatures sig ON sig.id = (
                        SELECT id FROM signatures WHERE script_version_id = v.id ORDER BY id DESC LIMIT 1)
                WHERE jt.agent_id = ? AND jt.state = 'queued' AND j.status IN ('pending', 'running')
                ORDER BY j.id`, agentID)
	if err != nil {
		return nil, fmt.Errorf("store: кандидаты выдачи %s: %w", agentID, err)
	}
	defer rows.Close()
	out := []DispatchCandidate{}
	for rows.Next() {
		var c DispatchCandidate
		var pilot, expires, targets, catalogKey, scriptKind sql.NullString
		var jobPilot int
		if err := rows.Scan(&c.JobID, &c.JobName, &c.Kind, &jobPilot,
			&c.VersionID, &c.Version, &c.Status, &c.Content, &c.SHA256, &pilot, &c.Category,
			&catalogKey, &scriptKind,
			&c.SignedBy, &c.SignedSHA, &expires,
			&c.Total, &c.Done, &c.Delivered, &targets); err != nil {
			return nil, fmt.Errorf("store: кандидаты выдачи %s: строка: %w", agentID, err)
		}
		c.IsPilot = jobPilot == 1
		c.CatalogKey = catalogKey.String
		switch {
		case scriptKind.String == gate.KindScript:
			c.ChangesSystem = true
		case scriptKind.String == gate.KindCatalog:
			tpl, err := catalog.Get(c.CatalogKey)
			c.ChangesSystem = err == nil && !tpl.ReadOnly
		}
		for _, tg := range strings.Split(targets.String, ",") {
			if tg != "" {
				c.Targets = append(c.Targets, tg)
			}
		}
		c.PilotOK = pilot.String == "1" || (pilot.Valid && pilot.String == "1")
		if expires.Valid && expires.String != "" {
			t, err := time.Parse(time.RFC3339Nano, expires.String)
			if err != nil {
				return nil, fmt.Errorf("store: срок подписи %s: %w", expires.String, err)
			}
			c.Expires = t
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// MarkTargetSent — конверт выдан агенту: queued → sent.
func (s *Store) MarkTargetSent(ctx context.Context, jobID int64, agentID, envelope string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: транзакция выдачи: %w", err)
	}
	defer tx.Rollback()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	res, err := tx.ExecContext(ctx, `
                UPDATE job_targets SET state = 'sent', envelope = ?, sent_at = ?, updated_at = ?
                WHERE job_id = ? AND agent_id = ? AND state = 'queued'`,
		envelope, now, now, jobID, agentID)
	if err != nil {
		return fmt.Errorf("store: цель %s: выдача: %w", agentID, err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return fmt.Errorf("%w: цель %s уже не в очереди", ErrScriptState, agentID)
	}
	var name string
	if err := tx.QueryRowContext(ctx, `SELECT name FROM jobs WHERE id = ?`, jobID).Scan(&name); err != nil {
		return fmt.Errorf("store: задание %d: %w", jobID, err)
	}
	detail, err := json.Marshal(map[string]any{"job": jobID, "agent": agentID})
	if err != nil {
		return fmt.Errorf("store: сводка выдачи: %w", err)
	}
	if _, err := audit.Append(ctx, tx, audit.Entry{
		Actor: ActorAgentAPI, Action: "job_dispatch", Target: name, Result: "ok", Detail: string(detail),
	}); err != nil {
		return err
	}
	return tx.Commit()
}

// MarkTargetExpired — просроченная подпись: цель не получает задание
// и помечается expired (навсегда: задание не будет выдано позднее).
func (s *Store) MarkTargetExpired(ctx context.Context, jobID int64, agentID, reason string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: транзакция expired: %w", err)
	}
	defer tx.Rollback()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	res, err := tx.ExecContext(ctx, `
                UPDATE job_targets SET state = 'expired', error = ?, updated_at = ?
                WHERE job_id = ? AND agent_id = ? AND state = 'queued'`, reason, now, jobID, agentID)
	if err != nil {
		return fmt.Errorf("store: цель %s: expired: %w", agentID, err)
	}
	if n, _ := res.RowsAffected(); n == 1 {
		var name string
		if err := tx.QueryRowContext(ctx, `SELECT name FROM jobs WHERE id = ?`, jobID).Scan(&name); err != nil {
			return fmt.Errorf("store: задание %d: %w", jobID, err)
		}
		detail, err := json.Marshal(map[string]any{"job": jobID, "agent": agentID, "reason": reason})
		if err != nil {
			return fmt.Errorf("store: сводка expired: %w", err)
		}
		if _, err := audit.Append(ctx, tx, audit.Entry{
			Actor: ActorAgentAPI, Action: "job_expired", Target: name, Result: "fail", Detail: string(detail),
		}); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ActorAgentAPI — актор записей аудита при выдаче заданий (тот же,
// что в агентском API).
const ActorAgentAPI = "agent-api"

// --- внутренние -------------------------------------------------------------

func (s *Store) jobTargets(ctx context.Context, jobID int64) ([]JobTargetRow, error) {
	rows, err := s.db.QueryContext(ctx, `
                SELECT agent_id, state, result, error, sent_at, updated_at, metric_before, metric_after
                FROM job_targets WHERE job_id = ? ORDER BY id`, jobID)
	if err != nil {
		return nil, fmt.Errorf("store: цели задания %d: %w", jobID, err)
	}
	defer rows.Close()
	out := []JobTargetRow{}
	for rows.Next() {
		var t JobTargetRow
		if err := rows.Scan(&t.AgentID, &t.State, &t.Result, &t.Error, &t.SentAt, &t.UpdatedAt,
			&t.MetricBefore, &t.MetricAfter); err != nil {
			return nil, fmt.Errorf("store: цели задания %d: строка: %w", jobID, err)
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func latestSignatureTx(ctx context.Context, tx *sql.Tx, versionID int64) (SignatureRow, error) {
	var r SignatureRow
	err := tx.QueryRowContext(ctx, `
                SELECT id, sha256, signed_by, signed_at, expires_at, signature
                FROM signatures WHERE script_version_id = ? ORDER BY id DESC LIMIT 1`, versionID).
		Scan(&r.ID, &r.SHA256, &r.SignedBy, &r.SignedAt, &r.ExpiresAt, &r.Signature)
	if errors.Is(err, sql.ErrNoRows) {
		return SignatureRow{}, fmt.Errorf("%w: версии %d нет подписи", ErrScriptState, versionID)
	}
	if err != nil {
		return SignatureRow{}, fmt.Errorf("store: подпись версии %d: %w", versionID, err)
	}
	return r, nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
