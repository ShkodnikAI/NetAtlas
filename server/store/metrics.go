// Хранилище и уплотнение метрик качества сети (NR-008). Сырые
// значения хранятся 48 часов, 5-минутные агрегаты — 30 суток,
// часовые — 1 год. Уплотнение идемпотентно: повторный запуск в
// те же окна ничего не меняет.
package store

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Сроки хранения (наряд NR-008).
const (
	MetricsRawKeep = 48 * time.Hour
	Metrics5mKeep  = 30 * 24 * time.Hour
	Metrics1hKeep  = 365 * 24 * time.Hour
	lossSampleSize = 20 // серия эхо-запросов на замер потерь
)

// MetricSample — одна сырая точка.
type MetricSample struct {
	AgentID string
	Target  string
	Kind    string
	Value   float64
	At      time.Time
}

// MetricAgg — агрегат окна; n — число слитых точек/окон (для
// повторного слияния опоздавших данных без потерь).
type MetricAgg struct {
	AgentID   string  `json:"agent_id"`
	Target    string  `json:"target"`
	Kind      string  `json:"kind"`
	Window    string  `json:"window"`
	Avg       float64 `json:"avg"`
	P95       float64 `json:"p95"`
	Max       float64 `json:"max"`
	LossCount int     `json:"loss_count"`
	N         int     `json:"-"`
}

// SaveMetricsRaw — порция сырых точек (одна транзакция).
func (s *Store) SaveMetricsRaw(ctx context.Context, samples []MetricSample) error {
	if len(samples) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: транзакция метрик: %w", err)
	}
	defer tx.Rollback()
	for _, m := range samples {
		if m.Target == "" || m.Kind == "" {
			continue
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO metrics_raw (agent_id, target, kind, value, at) VALUES (?, ?, ?, ?, ?)`,
			m.AgentID, m.Target, m.Kind, m.Value, m.At.UTC().Format(time.RFC3339Nano)); err != nil {
			return fmt.Errorf("store: метрика %s/%s: %w", m.AgentID, m.Kind, err)
		}
	}
	return tx.Commit()
}

// aggStore — запись агрегатов одного окна: INSERT OR REPLACE
// (повторное уплотнение тех же окон ничего не меняет).
func (s *Store) writeAgg(ctx context.Context, table string, rows []MetricAgg) error {
	if len(rows) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: транзакция агрегатов: %w", err)
	}
	defer tx.Rollback()
	for _, a := range rows {
		// Слияние с существующим окном: опоздавшие сырые точки не
		// затирают прежние. Среднее взвешивается числом точек,
		// максимум и потери суммируются-объединяются.
		var oldAvg, oldMax, oldP95 float64
		var oldLoss, oldN int
		err := tx.QueryRowContext(ctx,
			`SELECT avg, max, p95, loss_count, n FROM `+table+` WHERE agent_id=? AND target=? AND kind=? AND window=?`,
			a.AgentID, a.Target, a.Kind, a.Window).Scan(&oldAvg, &oldMax, &oldP95, &oldLoss, &oldN)
		avg, n := a.Avg, a.N
		if err == nil && oldN > 0 && n > 0 {
			avg = (oldAvg*float64(oldN) + a.Avg*float64(n)) / float64(oldN+n)
			n = oldN + n
			a.LossCount += oldLoss
			if a.Max < oldMax {
				a.Max = oldMax
			}
			if a.P95 < oldP95 {
				a.P95 = oldP95
			}
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT OR REPLACE INTO `+table+` (agent_id, target, kind, window, avg, p95, max, loss_count, n)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			a.AgentID, a.Target, a.Kind, a.Window, avg, a.P95, a.Max, a.LossCount, n); err != nil {
			return fmt.Errorf("store: агрегат %s: %w", table, err)
		}
	}
	return tx.Commit()
}

// CompactionResult — что сделало уплотнение.
type CompactionResult struct {
	RawRolled    int
	Agg5Rolled   int
	RawDeleted   int
	Agg5Deleted  int
	Agg1hDeleted int
}

// CompactMetrics — уплотнение: сырые → 5-минутные (старше 48 часов),
// 5-минутные → часовые (старше 30 суток), чистка старше года.
// Идемпотентно: окна перезаписываются теми же значениями.
func (s *Store) CompactMetrics(ctx context.Context, now time.Time) (CompactionResult, error) {
	var res CompactionResult
	rawCutoff := now.Add(-MetricsRawKeep)
	agg5Cutoff := now.Add(-Metrics5mKeep)
	agg1hCutoff := now.Add(-Metrics1hKeep)

	// 1. Сырые старше 48ч → 5-минутные окна (UTC).
	rows, err := s.aggFromRaw(ctx, rawCutoff)
	if err != nil {
		return res, err
	}
	if err := s.writeAgg(ctx, "metrics_agg_5m", rows); err != nil {
		return res, err
	}
	res.RawRolled = len(rows)
	r, err := s.deleteOlder(ctx, "metrics_raw", "at", rawCutoff, time.RFC3339Nano)
	if err != nil {
		return res, err
	}
	res.RawDeleted = r

	// 2. 5-минутные старше 30 суток → часовые.
	rows5, err := s.aggFromAgg(ctx, "metrics_agg_5m", agg5Cutoff, 6)
	if err != nil {
		return res, err
	}
	if err := s.writeAgg(ctx, "metrics_agg_1h", rows5); err != nil {
		return res, err
	}
	res.Agg5Rolled = len(rows5)
	r, err = s.deleteOlder(ctx, "metrics_agg_5m", "window", agg5Cutoff, "2006-01-02T15:04")
	if err != nil {
		return res, err
	}
	res.Agg5Deleted = r

	// 3. Часовые старше года — удалить.
	r, err = s.deleteOlder(ctx, "metrics_agg_1h", "window", agg1hCutoff, "2006-01-02T15:04")
	if err != nil {
		return res, err
	}
	res.Agg1hDeleted = r
	return res, nil
}

// aggFromRaw — группировка сырых точек старше cutoff в 5-минутные
// окна (UTC). p95 по отсортированному ряду: значение на позиции
// ⌈0.95·n⌉−1.
func (s *Store) aggFromRaw(ctx context.Context, cutoff time.Time) ([]MetricAgg, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT agent_id, target, kind, value, at FROM metrics_raw WHERE at < ?`,
		cutoff.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return nil, fmt.Errorf("store: сырые метрики: %w", err)
	}
	defer rows.Close()
	return groupSamples(rowsToSamples(rows), nil)
}

// aggFromAgg — свёртка агрегатов нижнего уровня в окна верхнего
// (для 5м → 1ч: 6 пятиминутных окон в часовом).
func (s *Store) aggFromAgg(ctx context.Context, table string, cutoff time.Time, windowsPer int) ([]MetricAgg, error) {
	layout := "2006-01-02T15:04"
	rows, err := s.db.QueryContext(ctx,
		`SELECT agent_id, target, kind, window, avg, p95, max, loss_count, n FROM `+table+` WHERE window < ?`,
		cutoff.UTC().Format(layout))
	if err != nil {
		return nil, fmt.Errorf("store: агрегаты %s: %w", table, err)
	}
	defer rows.Close()
	type cell struct {
		avg, p95, max []float64
		loss          int
	}
	groups := map[string]*cell{}
	var order []string
	for rows.Next() {
		var a MetricAgg
		if err := rows.Scan(&a.AgentID, &a.Target, &a.Kind, &a.Window, &a.Avg, &a.P95, &a.Max, &a.LossCount, &a.N); err != nil {
			return nil, fmt.Errorf("store: агрегат: %w", err)
		}
		w, err := time.Parse(layout, a.Window)
		if err != nil {
			return nil, fmt.Errorf("store: окно %q: %w", a.Window, err)
		}
		upper := w.Truncate(time.Hour).UTC().Format(layout)
		key := a.AgentID + "|" + a.Target + "|" + a.Kind + "|" + upper
		c, ok := groups[key]
		if !ok {
			c = &cell{}
			groups[key] = c
			order = append(order, key)
		}
		// Свёртка нижних окон: вклад каждой точки — её среднее.
		// Вклад нижнего окна — его среднее с весом n.
		for k := 0; k < a.N; k++ {
			c.avg = append(c.avg, a.Avg)
			c.p95 = append(c.p95, a.P95)
		}
		c.max = append(c.max, a.Max)
		c.loss += a.LossCount
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: агрегаты: %w", err)
	}
	out := make([]MetricAgg, 0, len(groups))
	for _, key := range order {
		parts := strings.SplitN(key, "|", 4)
		c := groups[key]
		out = append(out, MetricAgg{
			AgentID: parts[0], Target: parts[1], Kind: parts[2], Window: parts[3],
			Avg: mean(c.avg), P95: percentile(c.p95, 0.95), Max: maxOf(c.max),
			LossCount: c.loss, N: len(c.avg),
		})
	}
	return out, nil
}

// groupSamples — сырые точки → 5-минутные агрегаты.
func groupSamples(samples []MetricSample, err error) ([]MetricAgg, error) {
	if err != nil {
		return nil, err
	}
	layout := "2006-01-02T15:04"
	type cell struct {
		vals []float64
		loss int
	}
	groups := map[string]*cell{}
	var order []string
	for _, m := range samples {
		w := m.At.UTC().Truncate(5 * time.Minute).Format(layout)
		key := m.AgentID + "|" + m.Target + "|" + m.Kind + "|" + w
		c, ok := groups[key]
		if !ok {
			c = &cell{}
			groups[key] = c
			order = append(order, key)
		}
		c.vals = append(c.vals, m.Value)
		if m.Kind == "loss" {
			c.loss += int(m.Value*float64(lossSampleSize) + 0.5)
		}
	}
	out := make([]MetricAgg, 0, len(groups))
	for _, key := range order {
		parts := strings.SplitN(key, "|", 4)
		c := groups[key]
		out = append(out, MetricAgg{
			AgentID: parts[0], Target: parts[1], Kind: parts[2], Window: parts[3],
			Avg: mean(c.vals), P95: percentile(c.vals, 0.95), Max: maxOf(c.vals),
			LossCount: c.loss, N: len(c.vals),
		})
	}
	return out, nil
}

// rowsToSamples — чтение строк сырых метрик.
func rowsToSamples(rows interface {
	Next() bool
	Scan(dest ...any) error
	Close() error
}) []MetricSample {
	defer rows.Close()
	out := []MetricSample{}
	for rows.Next() {
		var m MetricSample
		var at string
		if err := rows.Scan(&m.AgentID, &m.Target, &m.Kind, &m.Value, &at); err != nil {
			continue
		}
		if t, err := time.Parse(time.RFC3339Nano, at); err == nil {
			m.At = t
			out = append(out, m)
		}
	}
	return out
}

// deleteOlder — удаление строк старше cutoff (по колонке-строке).
func (s *Store) deleteOlder(ctx context.Context, table, col string, cutoff time.Time, layout string) (int, error) {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM `+table+` WHERE `+col+` < ?`, cutoff.UTC().Format(layout))
	if err != nil {
		return 0, fmt.Errorf("store: чистка %s: %w", table, err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

func mean(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}
	var sum float64
	for _, x := range v {
		sum += x
	}
	return sum / float64(len(v))
}

func maxOf(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}
	m := v[0]
	for _, x := range v[1:] {
		if x > m {
			m = x
		}
	}
	return m
}

func percentile(v []float64, p float64) float64 {
	if len(v) == 0 {
		return 0
	}
	s := append([]float64(nil), v...)
	sort.Float64s(s)
	idx := int(p*float64(len(s))+0.999999) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(s) {
		idx = len(s) - 1
	}
	return s[idx]
}

// LatestMetrics — последние значения по каждому (target, kind)
// агента: для матрицы качества и правил узких мест.
func (s *Store) LatestMetrics(ctx context.Context, agentID string) ([]MetricAgg, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT target, kind, value, at FROM metrics_raw
		 WHERE agent_id = ? AND at = (
			SELECT MAX(at) FROM metrics_raw m2
			WHERE m2.agent_id = metrics_raw.agent_id AND m2.target = metrics_raw.target AND m2.kind = metrics_raw.kind)`,
		agentID)
	if err != nil {
		return nil, fmt.Errorf("store: последние метрики: %w", err)
	}
	defer rows.Close()
	out := []MetricAgg{}
	for rows.Next() {
		var target, kind, at string
		var value float64
		if err := rows.Scan(&target, &kind, &value, &at); err != nil {
			return nil, fmt.Errorf("store: метрика: %w", err)
		}
		out = append(out, MetricAgg{AgentID: agentID, Target: target, Kind: kind, Avg: value, P95: value, Max: value})
	}
	return out, rows.Err()
}

// SeriesMetrics — агрегаты за период (для графика).
func (s *Store) SeriesMetrics(ctx context.Context, agentID, target, kind string, from, to time.Time, hourly bool) ([]MetricAgg, error) {
	table := "metrics_agg_5m"
	layout := "2006-01-02T15:04"
	if hourly {
		table = "metrics_agg_1h"
		layout = "2006-01-02T15:04"
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT agent_id, target, kind, window, avg, p95, max, loss_count FROM `+table+
			` WHERE agent_id = ? AND target = ? AND kind = ? AND window >= ? AND window <= ? ORDER BY window`,
		agentID, target, kind, from.UTC().Format(layout), to.UTC().Format(layout))
	if err != nil {
		return nil, fmt.Errorf("store: ряд метрик: %w", err)
	}
	defer rows.Close()
	out := []MetricAgg{}
	for rows.Next() {
		var a MetricAgg
		if err := rows.Scan(&a.AgentID, &a.Target, &a.Kind, &a.Window, &a.Avg, &a.P95, &a.Max, &a.LossCount); err != nil {
			return nil, fmt.Errorf("store: агрегат: %w", err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
