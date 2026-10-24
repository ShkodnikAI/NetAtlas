// Тесты SNMP-разностей (NR-008): переполнение счётчика и загрузка.
package metrics

import "testing"

// Переполнение 32-битного счётчика: cur < prev → через границу.
func TestCounterDeltaWrap(t *testing.T) {
	if got := counterDelta(4e9, 1e8); got < 0 || got > 5e8 {
		t.Fatalf("переполнение: %v", got)
	}
	if got := counterDelta(100, 250); got != 150 {
		t.Fatalf("обычная разность: %v, хочу 150", got)
	}
	if got := counterDelta(100, 100); got != 0 {
		t.Fatalf("без изменений: %v", got)
	}
}

// Загрузка порта: (in+out)*8 / dt / linkBps × 100.
func TestPortUtilCalc(t *testing.T) {
	// 1 Гбит/с линк, 100% за 5 минут: 1e9 бит/с × 300 с / 8 = 37.5 ГБ.
	const linkBps = 1e9
	in := 3.75e10 // байт за интервал
	util := (in + 0) * 8 / (5 * 60) / linkBps * 100
	if util < 99.9 || util > 100.1 {
		t.Fatalf("загрузка %v, хочу ~100", util)
	}
}
