// Тесты прогноза заполнения диска (NR-009): известный наклон,
// стоящий и убывающий ряд, мало данных, шум.
package rules

import (
	"fmt"
	"testing"
)

func day(n int) string {
	// 2026-09-01 + n дней (без библиотечных арифметик даты — строки
	// сортируются лексикографически).
	base := []int{1, 0, 0} // день, месяц, год
	_ = base
	d := n + 1
	m := 9
	if d > 30 {
		d -= 30
		m = 10
	}
	return fmt.Sprintf("2026-%02d-%02d", m, d)
}

func points(used []float64, capacity float64) []Point {
	out := make([]Point, len(used))
	for i, u := range used {
		out[i] = Point{Day: day(i), Used: u, Capacity: capacity}
	}
	return out
}

// Растущий ряд: известный наклон +100/день, до полного 4 дня.
func TestForecastRisingKnownSlope(t *testing.T) {
	// 1600, 1700, ..., 2200 — ровно +100 в день (7 точек).
	used := []float64{1600, 1700, 1800, 1900, 2000, 2100, 2200}
	f := ForecastDisk(points(used, 2600))
	if f.Insufficient != "" {
		t.Fatalf("прогноз не выдан: %s", f.Insufficient)
	}
	if f.SlopePerDay < 99.9 || f.SlopePerDay > 100.1 {
		t.Fatalf("наклон %v, хочу ~100", f.SlopePerDay)
	}
	if f.DaysToFull == nil || *f.DaysToFull != 4 {
		t.Fatalf("days_to_full = %v, хочу 4", f.DaysToFull)
	}
	if f.Confidence < 0.99 {
		t.Fatalf("уровень уверенности %v, хочу ~1", f.Confidence)
	}
}

// Стоящий ряд: наклон ~0 — прогноз не выдаётся.
func TestForecastSteady(t *testing.T) {
	used := []float64{1000, 1000, 1000, 1000, 1000, 1000, 1000}
	f := ForecastDisk(points(used, 2600))
	if f.Insufficient != "" {
		t.Fatalf("стоящий ряд: %s", f.Insufficient)
	}
	if f.SlopePerDay != 0 {
		t.Fatalf("наклон %v, хочу 0", f.SlopePerDay)
	}
	if f.DaysToFull != nil {
		t.Fatalf("days_to_full должен отсутствовать: %v", *f.DaysToFull)
	}
}

// Убывающий ряд: очистка диска — days_to_full отсутствует.
func TestForecastFalling(t *testing.T) {
	used := []float64{2200, 2100, 2000, 1900, 1800, 1700, 1600}
	f := ForecastDisk(points(used, 2600))
	if f.Insufficient != "" {
		t.Fatalf("прогноз не выдан: %s", f.Insufficient)
	}
	if f.SlopePerDay >= 0 {
		t.Fatalf("наклон %v, хочу отрицательный", f.SlopePerDay)
	}
	if f.DaysToFull != nil {
		t.Fatalf("убывающий ряд не переполнится: %v", *f.DaysToFull)
	}
}

// Мало точек: 6 — insufficient_data.
func TestForecastFewPoints(t *testing.T) {
	used := []float64{1600, 1700, 1800, 1900, 2000, 2100}
	f := ForecastDisk(points(used, 2600))
	if f.Insufficient == "" {
		t.Fatal("6 точек дали прогноз")
	}
	if f.DaysToFull != nil {
		t.Fatal("должно отсутствовать days_to_full")
	}
}

// Шумные данные: R² ниже 0,5 — прогноз не выдаётся.
func TestForecastNoisy(t *testing.T) {
	used := []float64{1000, 2400, 1100, 2500, 1000, 2300, 1200, 2400}
	f := ForecastDisk(points(used, 2600))
	if f.Insufficient == "" {
		t.Fatalf("шумные данные дали прогноз: %+v", f)
	}
	if f.Confidence >= MinR2 {
		t.Fatalf("уровень уверенности %v, хочу < %v", f.Confidence, MinR2)
	}
}

// История длиннее 30 дней: берутся последние 30.
func TestForecastTrimsTo30(t *testing.T) {
	var used []float64
	for i := 0; i < 35; i++ {
		used = append(used, float64(1000+i*100))
	}
	f := ForecastDisk(points(used, 999999))
	if f.Insufficient != "" || f.DaysToFull == nil {
		t.Fatalf("прогноз: %+v", f)
	}
	// Наклон по последним 30 точкам всё ещё 100/день.
	if f.SlopePerDay < 99.9 || f.SlopePerDay > 100.1 {
		t.Fatalf("наклон %v, хочу ~100", f.SlopePerDay)
	}
}
