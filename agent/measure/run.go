package measure

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

//go:embed scripts/netstate.ps1
var scriptsFS embed.FS

// Limits — границы замеров (наряд NR-008).
const (
	LossSeries     = 20       // серия эхо-запросов
	DailyLimitByte = 20 << 20 // не больше 20 МБ в сутки на агента
	BlobMax        = 8 << 20  // предел замера скорости
	CPULimitPct    = 70       // остановка при загрузке CPU выше
	NetLimitPct    = 50       // или сети выше 50% канала
)

// Sample — одна точка отчёта.
type Sample struct {
	Target string  `json:"target"`
	Metric string  `json:"metric"`
	Value  float64 `json:"value"`
}

// Envelope — тело POST /agent/v1/metrics (схема версии 1).
type Envelope struct {
	Kind        string    `json:"kind"`
	SchemaVer   int       `json:"schema_ver"`
	CollectedAt time.Time `json:"collected_at"`
	Samples     []Sample  `json:"samples"`
}

// NetState — состояние машины из встроенного сценария (шлюз,
// загрузка CPU, счётчики адаптеров, скорость линка).
type NetState struct {
	Gateway string  `json:"gateway"`
	CPULoad float64 `json:"cpuLoad"`
	RxBytes float64 `json:"rxBytes"`
	TxBytes float64 `json:"txBytes"`
	LinkBps float64 `json:"linkBps"`
}

// StateProvider — состояние машины (Windows: встроенный PS-сценарий;
// тесты: подстава).
type StateProvider interface {
	State(ctx context.Context) (NetState, error)
}

// Prober — серия эхо-запросов (Windows: IcmpSendEcho; тесты: подстава).
type Prober interface {
	Ping(ctx context.Context, host string, attempts int) ([]float64, error)
	Close() error
}

// Limiter — соблюдение лимитов: CPU и сети.
type Limiter struct {
	CPUPct    float64
	NetUsePct float64
}

// Overloaded — замеры стоит остановить (CPU >70% или сеть >50%).
func (l Limiter) Overloaded() (bool, string) {
	if l.CPUPct > CPULimitPct {
		return true, fmt.Sprintf("cpu %.0f%% > %d%%", l.CPUPct, CPULimitPct)
	}
	if l.NetUsePct > NetLimitPct {
		return true, fmt.Sprintf("network %.0f%% > %d%%", l.NetUsePct, NetLimitPct)
	}
	return false, ""
}

// psState — провайдер состояния через встроенный сценарий.
type psState struct{}

// State — разбор JSON-вывода сценария netstate.
func (psState) State(ctx context.Context) (NetState, error) {
	body, err := scriptsFS.ReadFile("scripts/netstate.ps1")
	if err != nil {
		return NetState{}, err
	}
	out, err := runPowerShell(ctx, body)
	if err != nil {
		return NetState{}, err
	}
	var st NetState
	if err := json.Unmarshal(out, &st); err != nil {
		return NetState{}, fmt.Errorf("measure: состояние: %w", err)
	}
	return st, nil
}

// NewStateProvider — провайдер по умолчанию.
func NewStateProvider() StateProvider { return psState{} }

// Volume — суточный лимит объёма замеров (счётчик в памяти + файл
// ведёт агент; здесь — инжектируемая точка).
type Volume struct {
	Used int64
	day  string
	Max  int64
}

// NewVolume — счётчик с лимитом DailyLimitByte.
func NewVolume(now time.Time) *Volume {
	return &Volume{day: now.Format("2006-01-02"), Max: DailyLimitByte}
}

// Roll — новый день: счётчик обнуляется.
func (v *Volume) Roll(now time.Time) {
	d := now.Format("2006-01-02")
	if d != v.day {
		v.day = d
		v.Used = 0
	}
}

// Add — добавить объём; false — лимит исчерпан (лёгкие замеры
// продолжаются, тяжёлые пропускаются).
func (v *Volume) Add(n int64) bool {
	if v.Used+n > v.Max {
		return false
	}
	v.Used += n
	return true
}

// measureOptions — параметры одного цикла замеров.
type Options struct {
	ServerHost string // хост:порт сервера (TCP/blob)
	ServerURL  string // https://...
	SpeedURL   string // URL скорости интернета; пусто = выключено
	Now        time.Time
	Prober     Prober
	State      StateProvider
	Volume     *Volume
	HTTP       *http.Client
}

// RunOnce — цикл лёгких замеров: шлюз, сервер, DNS, TCP; тяжёлые
// (скорость, bufferbloat) — только в окне простоя и в лимите объёма.
func RunOnce(ctx context.Context, o Options) ([]Sample, error) {
	st, err := o.State.State(ctx)
	if err != nil {
		return nil, fmt.Errorf("measure: состояние: %w", err)
	}
	if blocked, why := (Limiter{CPUPct: st.CPULoad, NetUsePct: netUsePct(st)}).Overloaded(); blocked {
		return nil, fmt.Errorf("measure: замеры остановлены: %s", why)
	}
	samples := []Sample{}

	// Задержка/джиттер/потери: шлюз и сервер (если есть пробер).
	if o.Prober != nil {
		if st.Gateway != "" {
			rtts, err := o.Prober.Ping(ctx, st.Gateway, LossSeries)
			if err == nil {
				r := ComputeSeries(rtts, LossSeries)
				samples = append(samples,
					Sample{st.Gateway, "latency", r.LatencyMs},
					Sample{st.Gateway, "jitter", r.JitterMs},
					Sample{st.Gateway, "loss", lossRate(r)},
				)
			}
		}
		if host := hostOnly(o.ServerHost); host != "" {
			rtts, err := o.Prober.Ping(ctx, host, LossSeries)
			if err == nil {
				r := ComputeSeries(rtts, LossSeries)
				samples = append(samples,
					Sample{host, "latency", r.LatencyMs},
					Sample{host, "jitter", r.JitterMs},
					Sample{host, "loss", lossRate(r)},
				)
			}
		}
	}

	// DNS: время разрешения имени сервера.
	if host := hostOnly(o.ServerHost); host != "" {
		start := time.Now()
		_, err := net.DefaultResolver.LookupHost(ctx, host)
		if err == nil {
			samples = append(samples, Sample{"dns:" + host, "dns", float64(time.Since(start).Milliseconds())})
		}
	}

	// TCP-соединение до сервера.
	if o.ServerHost != "" {
		start := time.Now()
		conn, err := net.DialTimeout("tcp", o.ServerHost, 3*time.Second)
		if err == nil {
			conn.Close()
			samples = append(samples, Sample{o.ServerHost, "tcp", float64(time.Since(start).Milliseconds())})
		}
	}

	// Тяжёлые замеры — только в окне простоя 01:00–05:00.
	if !InQuietHours(o.Now) {
		return samples, nil
	}

	// Скорость до сервера: загрузка blob + выгрузка.
	if o.ServerURL != "" && o.Volume.Add(BlobMax) {
		if mbps, err := downloadSpeed(ctx, o, "/agent/v1/blob?bytes="+strconv.Itoa(BlobMax)); err == nil {
			samples = append(samples, Sample{o.ServerHost, "down_mbps", mbps})
		}
		if mbps, err := uploadSpeed(ctx, o); err == nil {
			samples = append(samples, Sample{o.ServerHost, "up_mbps", mbps})
		}
	}

	// Скорость интернета: только если владелец задал speed_url.
	if o.SpeedURL != "" && o.Volume.Add(BlobMax) {
		if mbps, err := urlSpeed(ctx, o.HTTP, o.SpeedURL, BlobMax); err == nil {
			samples = append(samples, Sample{"internet", "down_mbps", mbps})
		}
	}
	return samples, nil
}

// netUsePct — доля используемого канала (по счётчикам адаптеров
// относительно скорости линка; точность — состояние машины).
func netUsePct(st NetState) float64 {
	if st.LinkBps <= 0 {
		return 0
	}
	return (st.RxBytes + st.TxBytes) / st.LinkBps * 100
}

func lossRate(r Result) float64 {
	if r.Attempts == 0 {
		return 0
	}
	return float64(r.Lost) / float64(r.Attempts)
}

func hostOnly(hostPort string) string {
	if h, _, err := net.SplitHostPort(hostPort); err == nil {
		return h
	}
	return hostPort
}

// downloadSpeed — замер загрузки с сервера (blob).
func downloadSpeed(ctx context.Context, o Options, path string) (float64, error) {
	hc := o.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}
	start := time.Now()
	resp, err := hc.Get(strings.TrimSuffix(o.ServerURL, "/") + path)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	buf := make([]byte, 64<<10)
	var total int64
	for {
		n, err := resp.Body.Read(buf)
		total += int64(n)
		if err != nil {
			break
		}
	}
	return Mbps(total, time.Since(start)), nil
}

// uploadSpeed — замер выгрузки на сервер (blob).
func uploadSpeed(ctx context.Context, o Options) (float64, error) {
	hc := o.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}
	payload := make([]byte, BlobMax)
	start := time.Now()
	resp, err := hc.Post(strings.TrimSuffix(o.ServerURL, "/")+"/agent/v1/blob", "application/octet-stream", strings.NewReader(string(payload)))
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	return Mbps(BlobMax, time.Since(start)), nil
}

// urlSpeed — замер загрузки с внешнего адреса (speed_url владельца).
func urlSpeed(ctx context.Context, hc *http.Client, raw string, limit int64) (float64, error) {
	if _, err := url.Parse(raw); err != nil {
		return 0, err
	}
	if hc == nil {
		hc = http.DefaultClient
	}
	start := time.Now()
	resp, err := hc.Get(raw)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	buf := make([]byte, 64<<10)
	var total int64
	for total < limit {
		n, err := resp.Body.Read(buf)
		total += int64(n)
		if err != nil {
			break
		}
	}
	return Mbps(total, time.Since(start)), nil
}
