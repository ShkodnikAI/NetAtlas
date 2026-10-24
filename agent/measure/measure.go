// Package measure — замеры качества сети агентом (NR-008). Замеры
// не влияют на работу: лимит объёма (≤20 МБ/сутки), лёгкие замеры
// раз в 5 минут, тяжёлые — только в окне простоя 01:00–05:00,
// остановка при загрузке CPU >70 % или сети >50 % канала. Агент не
// слушает портов: только исходящие измерения.
package measure

import (
	"math"
	"time"
)

// Result — итог одной серии эхо-запросов (20 попыток).
type Result struct {
	LatencyMs float64 // средняя задержка успешных
	JitterMs  float64 // стандартное отклонение разностей соседних RTT
	Lost      int     // потеряно из Attempts
	Attempts  int
}

// ComputeSeries — расчёт из серии RTT: незавершённые эхо — потери.
func ComputeSeries(rtts []float64, attempts int) Result {
	if attempts <= 0 {
		attempts = len(rtts)
	}
	var ok []float64
	lost := attempts
	for _, r := range rtts {
		if r >= 0 && !math.IsNaN(r) && !math.IsInf(r, 0) {
			ok = append(ok, r)
			lost--
		}
	}
	res := Result{Lost: lost, Attempts: attempts}
	if len(ok) == 0 {
		return res
	}
	var sum float64
	for _, r := range ok {
		sum += r
	}
	res.LatencyMs = sum / float64(len(ok))
	res.JitterMs = jitter(ok)
	return res
}

// jitter — среднеквадратичное отклонение разностей соседних RTT
// (упрощение RFC 3550 для рядов одной серии).
func jitter(v []float64) float64 {
	if len(v) < 2 {
		return 0
	}
	var diffs []float64
	for i := 1; i < len(v); i++ {
		d := v[i] - v[i-1]
		diffs = append(diffs, d)
	}
	var sum float64
	for _, d := range diffs {
		sum += d
	}
	mean := sum / float64(len(diffs))
	var sq float64
	for _, d := range diffs {
		sq += (d - mean) * (d - mean)
	}
	return math.Sqrt(sq / float64(len(diffs)))
}

// Mbps — байт/секунду в Мбит/с.
func Mbps(bytes int64, d time.Duration) float64 {
	if d <= 0 {
		return 0
	}
	return float64(bytes) * 8 / d.Seconds() / 1e6
}

// InQuietHours — тяжёлые замеры разрешены только в окне 01:00–05:00
// локального времени.
func InQuietHours(now time.Time) bool {
	h := now.Hour()
	return h >= 1 && h < 5
}
