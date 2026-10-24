// Прогноз заполнения диска (NR-009): линейная регрессия методом
// наименьших квадратов по дневным точкам занятого места за последние
// 30 дней. Меньше 7 точек или R² ниже 0,5 — прогноз не выдаётся
// (insufficient_data). Формула и пример — docs/RULES.md.
package rules

import (
	"fmt"
	"math"
	"sort"
	"time"
)

// MinPoints — минимум дневных точек для прогноза.
const MinPoints = 7

// MinR2 — минимальный коэффициент детерминации.
const MinR2 = 0.5

// Point — дневная точка истории тома.
type Point struct {
	Day      string  `json:"day"` // YYYY-MM-DD
	Used     float64 `json:"used"`
	Capacity float64 `json:"capacity"`
}

// Forecast — результат прогноза.
type Forecast struct {
	DaysToFull   *int    `json:"days_to_full,omitempty"` // nil — не переполнится или данных мало
	Confidence   float64 `json:"confidence"`             // R²
	SlopePerDay  float64 `json:"slope_per_day"`          // байт/день
	Insufficient string  `json:"insufficient,omitempty"` // причина отсутствия прогноза
}

// ForecastDisk — прогноз по истории: точки сортируются по дню,
// остаются последние 30, регрессия по x = номер дня.
func ForecastDisk(points []Point) Forecast {
	if len(points) == 0 {
		return Forecast{Insufficient: "нет данных"}
	}
	sort.Slice(points, func(i, j int) bool { return points[i].Day < points[j].Day })
	if len(points) > 30 {
		points = points[len(points)-30:]
	}
	if len(points) < MinPoints {
		return Forecast{Insufficient: fmt.Sprintf("мало точек: %d из %d", len(points), MinPoints)}
	}

	// МНК: x — номер дня от первой точки, y — занято байт.
	n := float64(len(points))
	t0, err := time.Parse("2006-01-02", points[0].Day)
	if err != nil {
		return Forecast{Insufficient: "плохая дата"}
	}
	var sx, sy, sxx, sxy float64
	for _, p := range points {
		d, err := time.Parse("2006-01-02", p.Day)
		if err != nil {
			return Forecast{Insufficient: "плохая дата"}
		}
		x := d.Sub(t0).Hours() / 24
		y := p.Used
		sx += x
		sy += y
		sxx += x * x
		sxy += x * y
	}
	denom := n*sxx - sx*sx
	if denom == 0 {
		return Forecast{Insufficient: "вырожденный ряд"}
	}
	slope := (n*sxy - sx*sy) / denom
	intercept := (sy - slope*sx) / n

	// R² = 1 - SSres/SStot.
	var ssRes, ssTot float64
	meanY := sy / n
	for _, p := range points {
		d, _ := time.Parse("2006-01-02", p.Day)
		x := d.Sub(t0).Hours() / 24
		pred := slope*x + intercept
		ssRes += (p.Used - pred) * (p.Used - pred)
		ssTot += (p.Used - meanY) * (p.Used - meanY)
	}
	r2 := 1.0
	if ssTot > 0 {
		r2 = 1 - ssRes/ssTot
	}
	if r2 < MinR2 {
		return Forecast{Confidence: r2, SlopePerDay: slope, Insufficient: "данные шумные"}
	}

	res := Forecast{Confidence: r2, SlopePerDay: slope}
	// Переполнение: наклон положительный и есть ёмкость.
	last := points[len(points)-1]
	if slope > 0 && last.Capacity > last.Used {
		days := (last.Capacity - last.Used) / slope
		res.DaysToFull = intPtr(int(math.Ceil(days)))
	}
	return res
}

func intPtr(v int) *int { return &v }
