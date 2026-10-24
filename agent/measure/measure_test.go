// Тесты замеров (NR-008): расчёты серий, окно простоя, лимит
// объёма, остановка по загрузке, переполнение счётчиков SNMP.
package measure

import (
	"context"
	"errors"
	"math"
	"net"
	"testing"
	"time"
)

// Расчёт серии: средняя задержка, джиттер по разностям, потери.
func TestComputeSeries(t *testing.T) {
	// Ровный ряд без потерь: джиттер 0.
	r := ComputeSeries([]float64{10, 10, 10, 10}, 4)
	if r.Lost != 0 || r.LatencyMs != 10 || r.JitterMs != 0 {
		t.Fatalf("ровный ряд: %+v", r)
	}
	// Пила 10/12 с нулевым средним разностей: σ = 2.
	r = ComputeSeries([]float64{10, 12, 10, 12, 10}, 5)
	if r.JitterMs < 1.99 || r.JitterMs > 2.01 {
		t.Fatalf("джиттер %v, хочу ~2", r.JitterMs)
	}
	// Потери: -1 — потеряно.
	r = ComputeSeries([]float64{10, -1, 12, -1}, 20)
	if r.Lost != 18 || r.Attempts != 20 {
		t.Fatalf("потери (2 успешных из 20): %+v", r)
	}
	if r.LatencyMs != 11 {
		t.Fatalf("латентность по успешным: %v", r.LatencyMs)
	}
	// Всё потеряно: нули, не NaN.
	r = ComputeSeries([]float64{-1, -1, -1}, 3)
	if r.Lost != 3 || math.IsNaN(r.LatencyMs) || math.IsNaN(r.JitterMs) {
		t.Fatalf("всё потеряно: %+v", r)
	}
}

// Окно простоя: тяжёлые замеры только 01:00–04:59.
func TestInQuietHours(t *testing.T) {
	for h, want := range map[int]bool{0: false, 1: true, 2: true, 4: true, 5: false, 12: false, 23: false} {
		now := time.Date(2026, 10, 24, h, 0, 0, 0, time.Local)
		if InQuietHours(now) != want {
			t.Fatalf("час %d: %v, хочу %v", h, InQuietHours(now), want)
		}
	}
}

// Суточный лимит: 20 МБ, новый день обнуляет.
func TestVolumeLimit(t *testing.T) {
	v := NewVolume(time.Date(2026, 10, 24, 1, 0, 0, 0, time.Local))
	if !v.Add(19 << 20) {
		t.Fatal("19 МБ не поместились")
	}
	if v.Add(2 << 20) {
		t.Fatal("превышение 20 МБ принято")
	}
	if v.Used != 19<<20 {
		t.Fatalf("использовано %d", v.Used)
	}
	// Новый день — счётчик обнулён.
	v.Roll(time.Date(2026, 10, 25, 0, 30, 0, 0, time.Local))
	if v.Used != 0 {
		t.Fatalf("новый день: использовано %d", v.Used)
	}
}

// Лимитер: CPU >70% или сеть >50% — замеры остановлены.
func TestLimiter(t *testing.T) {
	if blocked, _ := (Limiter{CPUPct: 30, NetUsePct: 10}).Overloaded(); blocked {
		t.Fatal("спокойная машина заблокирована")
	}
	if blocked, why := (Limiter{CPUPct: 71, NetUsePct: 0}).Overloaded(); !blocked || why == "" {
		t.Fatal("CPU 71% не остановил замеры")
	}
	if blocked, _ := (Limiter{CPUPct: 70, NetUsePct: 0}).Overloaded(); blocked {
		t.Fatal("ровно 70% не должно останавливать")
	}
	if blocked, _ := (Limiter{CPUPct: 0, NetUsePct: 51}).Overloaded(); !blocked {
		t.Fatal("сеть 51% не остановила замеры")
	}
}

type fakeState struct {
	st  NetState
	err error
}

func (f fakeState) State(ctx context.Context) (NetState, error) { return f.st, f.err }

type fakeProber struct{ rtts []float64 }

func (f fakeProber) Ping(ctx context.Context, host string, attempts int) ([]float64, error) {
	// Полная серия: сколько не вернули — те потери.
	out := make([]float64, attempts)
	copy(out, f.rtts)
	for i := len(f.rtts); i < attempts; i++ {
		out[i] = -1
	}
	return out, nil
}
func (fakeProber) Close() error { return nil }

// Цикл лёгких замеров днём: шлюз/сервер/DNS/TCP, без скоростей.
func TestRunOnceLight(t *testing.T) {
	// Настоящий слушатель: TCP-замер должен показать время соединения.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("слушатель: %v", err)
	}
	defer ln.Close()
	o := Options{
		ServerHost: ln.Addr().String(),
		ServerURL:  "https://" + ln.Addr().String(),
		Now:        time.Date(2026, 10, 24, 12, 0, 0, 0, time.Local),
		Prober:     fakeProber{rtts: []float64{5, 6, 5, 5, 5, 6, 5, 5, 6, 5, 5, 6, 5, 5, 6, 5, 5, 6, 5, 5}},
		State:      fakeState{st: NetState{Gateway: "192.168.1.1", CPULoad: 10, LinkBps: 1e9}},
		Volume:     NewVolume(time.Now()),
	}
	samples, err := RunOnce(context.Background(), o)
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	metrics := map[string]bool{}
	for _, s := range samples {
		metrics[s.Metric] = true
	}
	for _, m := range []string{"latency", "jitter", "loss", "tcp"} {
		if !metrics[m] {
			t.Fatalf("нет метрики %s: %+v", m, samples)
		}
	}
	for _, s := range samples {
		if s.Metric == "down_mbps" || s.Metric == "up_mbps" {
			t.Fatalf("днём тяжёлых замеров быть не должно: %+v", samples)
		}
	}
}

// Остановка по загрузке CPU: замеры не выполняются.
func TestRunOnceStopsWhenBusy(t *testing.T) {
	o := Options{
		Now:    time.Date(2026, 10, 24, 12, 0, 0, 0, time.Local),
		Prober: fakeProber{},
		State:  fakeState{st: NetState{Gateway: "192.168.1.1", CPULoad: 90}},
		Volume: NewVolume(time.Now()),
	}
	if _, err := RunOnce(context.Background(), o); err == nil {
		t.Fatal("замеры при CPU 90% прошли")
	}
	// Ошибка состояния — тоже ошибка.
	o.State = fakeState{err: errors.New("нет PS")}
	if _, err := RunOnce(context.Background(), o); err == nil {
		t.Fatal("ошибка состояния проглотилась")
	}
}
