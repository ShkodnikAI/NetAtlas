// Тесты уплотнения метрик (NR-008): границы окон, идемпотентность,
// p95 и счёт потерь.
package store

import (
	"context"
	"testing"
	"time"
)

func base() time.Time { return time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC) }

// Сырые старше 48ч уходят в 5-минутные агрегаты, свежие остаются.
func TestCompactRawTo5m(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	now := base()
	old := now.Add(-49 * time.Hour)
	fresh := now.Add(-1 * time.Hour)
	err := s.SaveMetricsRaw(ctx, []MetricSample{
		{AgentID: "agent:a", Target: "192.168.1.1", Kind: "latency", Value: 10, At: old},
		{AgentID: "agent:a", Target: "192.168.1.1", Kind: "latency", Value: 20, At: old.Add(2 * time.Minute)},
		{AgentID: "agent:a", Target: "192.168.1.1", Kind: "loss", Value: 0.1, At: old},
		{AgentID: "agent:a", Target: "192.168.1.1", Kind: "latency", Value: 5, At: fresh},
	})
	if err != nil {
		t.Fatalf("SaveMetricsRaw: %v", err)
	}
	res, err := s.CompactMetrics(ctx, now)
	if err != nil {
		t.Fatalf("CompactMetrics: %v", err)
	}
	// 3 сырых точки → 2 агрегатных строки (latency-окно и loss-окно).
	if res.RawRolled != 2 {
		t.Fatalf("свёрнуто сырых %d, хочу 2 (две группы kind)", res.RawRolled)
	}
	if res.RawDeleted != 3 {
		t.Fatalf("удалено сырых %d, хочу 3", res.RawDeleted)
	}
	// Свежая точка (моложе 48ч) осталась сырой — не свёрнута и не удалена.
	var freshVal float64
	if err := s.DB().QueryRow(`SELECT value FROM metrics_raw WHERE kind='latency' AND value = 5`).Scan(&freshVal); err != nil {
		t.Fatalf("свежая точка потеряна: %v", err)
	}
	// Окно старое: до уплотнения не читается (свежие окна пусты),
	// проверим содержимое агрегатов напрямую.
	var avg float64
	if err := s.DB().QueryRow(`SELECT avg FROM metrics_agg_5m WHERE kind='latency' LIMIT 1`).Scan(&avg); err != nil {
		t.Fatalf("агрегат: %v", err)
	}
	if avg != 15 { // 10 и 20 в одном 5-минутном окне
		t.Fatalf("среднее окна %v, хочу 15", avg)
	}
	var loss int
	if err := s.DB().QueryRow(`SELECT loss_count FROM metrics_agg_5m WHERE kind='loss' LIMIT 1`).Scan(&loss); err != nil {
		t.Fatalf("потери: %v", err)
	}
	if loss != 2 { // 0.1 × 20
		t.Fatalf("потерь в окне %d, хочу 2", loss)
	}
}

// Идемпотентность и повторная свёртка того же окна: агент с
// отставшими часами присылает точку в уже свёрнутое окно — повторное
// уплотнение обязано перезаписать окно (INSERT OR REPLACE), а не
// упасть и не задвоить.
func TestCompactIdempotent(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	now := base()
	old := now.Add(-49 * time.Hour)
	_ = s.SaveMetricsRaw(ctx, []MetricSample{
		{AgentID: "agent:a", Target: "g", Kind: "latency", Value: 10, At: old},
	})
	if _, err := s.CompactMetrics(ctx, now); err != nil {
		t.Fatalf("первое уплотнение: %v", err)
	}
	var c1 int
	_ = s.DB().QueryRow(`SELECT COUNT(*) FROM metrics_agg_5m`).Scan(&c1)
	if c1 != 1 {
		t.Fatalf("окон после первого прогона %d, хочу 1", c1)
	}

	// Опоздавшая точка в то же окно.
	if err := s.SaveMetricsRaw(ctx, []MetricSample{
		{AgentID: "agent:a", Target: "g", Kind: "latency", Value: 30, At: old.Add(2 * time.Minute)},
	}); err != nil {
		t.Fatalf("опоздавшая точка: %v", err)
	}
	if _, err := s.CompactMetrics(ctx, now); err != nil {
		t.Fatalf("второе уплотнение (то же окно): %v", err)
	}
	var c2, n int
	var avg float64
	_ = s.DB().QueryRow(`SELECT COUNT(*) FROM metrics_agg_5m`).Scan(&c2)
	if c2 != 1 {
		t.Fatalf("повтор задвоил окна: %d → %d", c1, c2)
	}
	if err := s.DB().QueryRow(`SELECT n, avg FROM metrics_agg_5m GROUP BY agent_id, target, kind, window`).Scan(&n, &avg); err != nil {
		t.Fatalf("чтение окна: %v", err)
	}
	if n != 2 || avg != 20 { // 10 и 30 в одном окне
		t.Fatalf("окно не перезаписано: точек %d, avg %v", n, avg)
	}
	var raw int
	_ = s.DB().QueryRow(`SELECT COUNT(*) FROM metrics_raw`).Scan(&raw)
	if raw != 0 {
		t.Fatalf("сырых после уплотнения %d, хочу 0", raw)
	}
}

// 5-минутные старше 30 суток сворачиваются в часовые.
func TestCompact5mTo1h(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	now := base()
	old := now.Add(-31 * 24 * time.Hour)
	// Шесть 5-минутных окон одного часа.
	points := []MetricSample{}
	for i := 0; i < 6; i++ {
		points = append(points, MetricSample{
			AgentID: "agent:a", Target: "g", Kind: "latency",
			Value: float64(10 + i), At: old.Add(time.Duration(i*5) * time.Minute),
		})
	}
	if err := s.SaveMetricsRaw(ctx, points); err != nil {
		t.Fatalf("SaveMetricsRaw: %v", err)
	}
	if _, err := s.CompactMetrics(ctx, now); err != nil {
		t.Fatalf("уплотнение 1: %v", err)
	}
	// Промежуточные 5-минутные окна созданы, но тоже старше 30 суток —
	// сворачиваются во вторую ступень тем же запуском? Нет: ступень 2
	// работает по данным, созданным ДО запуска; окна ступени 1
	// сворачиваются на следующем запуске.
	if _, err := s.CompactMetrics(ctx, now); err != nil {
		t.Fatalf("уплотнение 2: %v", err)
	}
	var c1, c5 int
	_ = s.DB().QueryRow(`SELECT COUNT(*) FROM metrics_agg_1h`).Scan(&c1)
	_ = s.DB().QueryRow(`SELECT COUNT(*) FROM metrics_agg_5m`).Scan(&c5)
	if c1 != 1 {
		t.Fatalf("часовых окон %d, хочу 1", c1)
	}
	if c5 != 0 {
		t.Fatalf("5-минутных окон осталось %d, хочу 0", c5)
	}
	var avg float64
	_ = s.DB().QueryRow(`SELECT avg FROM metrics_agg_1h LIMIT 1`).Scan(&avg)
	if avg != 12.5 { // среднее 10..15
		t.Fatalf("часовое среднее %v, хочу 12.5", avg)
	}
}

// p95 по окну: значение на границе 95-го процентиля.
func TestCompactP95(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	now := base()
	old := now.Add(-49 * time.Hour)
	// 20 точек одного окна: значения 1..20 → p95 = 19.
	points := []MetricSample{}
	for i := 1; i <= 20; i++ {
		points = append(points, MetricSample{
			AgentID: "agent:a", Target: "g", Kind: "latency",
			Value: float64(i), At: old.Add(time.Duration(i) * time.Second),
		})
	}
	if err := s.SaveMetricsRaw(ctx, points); err != nil {
		t.Fatalf("SaveMetricsRaw: %v", err)
	}
	if _, err := s.CompactMetrics(ctx, now); err != nil {
		t.Fatalf("уплотнение: %v", err)
	}
	var p95 float64
	if err := s.DB().QueryRow(`SELECT p95 FROM metrics_agg_5m WHERE kind='latency'`).Scan(&p95); err != nil {
		t.Fatalf("p95: %v", err)
	}
	if p95 != 19 {
		t.Fatalf("p95 %v, хочу 19", p95)
	}
}
