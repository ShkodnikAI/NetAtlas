// Цикл опроса агента (NR-006): после регистрации агент сам
// подключается к серверу — checkin (интервал из ответа) и
// инвентарь. При потере связи отчёты уходят в дисковую очередь
// (agent/spool), при восстановлении отправляются по порядку;
// паузы повторов растут до 15 минут.
package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"path/filepath"
	"time"

	"github.com/ShkodnikAI/NetAtlas/agent/collect"
	"github.com/ShkodnikAI/NetAtlas/agent/spool"
)

// BackoffBase — начальная пауза повторов; BackoffMax — предел
// (наряд: до 15 минут).
const (
	BackoffBase = 30 * time.Second
	BackoffMax  = 15 * time.Minute
)

// Runner — цикл агента.
type Runner struct {
	Server string
	Dir    string
	// Interval — базовый интервал опроса; обновляется из checkin.
	Interval time.Duration
	// Collectors — сборщики; nil → DefaultCollectors.
	Collectors []collect.Collector

	transport Transport
	spool     *spool.Spool

	// Точки подмены в тестах.
	Now         func() time.Time
	Sleep       func(ctx context.Context, d time.Duration) error
	backoffBase time.Duration
	backoffMax  time.Duration
}

// NewRunner собирает раннер: TLS из каталога состояния, очередь в
// подкаталоге spool.
func NewRunner(serverURL, dir string) (*Runner, error) {
	client, err := NewClient(serverURL, dir)
	if err != nil {
		return nil, err
	}
	sp, err := spool.Open(SpoolDir(dir), spool.DefaultMaxBytes)
	if err != nil {
		return nil, err
	}
	return &Runner{
		Server:      serverURL,
		Dir:         dir,
		Interval:    DefaultPollInterval,
		transport:   client,
		spool:       sp,
		Now:         time.Now,
		Sleep:       defaultSleep,
		backoffBase: BackoffBase,
		backoffMax:  BackoffMax,
	}, nil
}

// SpoolDir — подкаталог очереди внутри каталога состояния.
func SpoolDir(dir string) string { return filepath.Join(dir, "spool") }

// CollectOnce — сбор и печать отчёта без сети (run --once --dry).
func CollectOnce(collectors []collect.Collector) ([]byte, error) {
	if collectors == nil {
		collectors = collect.DefaultCollectors(collect.NewPowerShellRunner())
	}
	rep := collect.BuildReport(context.Background(), hostname(), collectors, time.Now())
	return json.Marshal(rep)
}

// RunOnce — один цикл: очередь → checkin → сбор и отправка.
func (r *Runner) RunOnce(ctx context.Context) error {
	if r.Collectors == nil {
		r.Collectors = collect.DefaultCollectors(collect.NewPowerShellRunner())
	}
	if err := r.drainSpool(ctx); err != nil {
		return err
	}
	check, err := r.transport.Checkin(ctx)
	if err != nil {
		return err
	}
	// Интервал опроса приходит от сервера; 0 — оставить текущий.
	if check.PollSec > 0 {
		r.Interval = time.Duration(check.PollSec) * time.Second
	}
	body, err := r.buildInventory()
	if err != nil {
		return err
	}
	if err := r.transport.SendInventory(ctx, body); err != nil {
		// Связь потеряна после checkin: отчёт в очередь, цикл
		// считается ошибкой (растущая пауза).
		if perr := r.spool.Push(body); perr != nil {
			return fmt.Errorf("agent: очередь: %w", perr)
		}
		return err
	}
	return nil
}

// Run — цикл до остановки контекста. Ошибки цикла удваивают паузу
// (от BackoffBase до BackoffMax), успех возвращает базовый интервал.
func (r *Runner) Run(ctx context.Context) error {
	base := r.backoffBase
	if base <= 0 {
		base = BackoffBase
	}
	max := r.backoffMax
	if max <= 0 {
		max = BackoffMax
	}
	pause := r.Interval
	fails := 0
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		err := r.RunOnce(ctx)
		if err == nil {
			fails = 0
			pause = r.Interval
		} else {
			log.Printf("agent: цикл: %v", err)
			// Растущая пауза: base * 2^fails, не больше max.
			grown := base << fails
			if grown > max || grown <= 0 {
				grown = max
			}
			pause = grown
			fails++
			if fails > 32 {
				fails = 32
			}
		}
		if err := r.sleep(ctx, pause); err != nil {
			return nil
		}
	}
}

// drainSpool отправляет накопленное по порядку; первая ошибка
// останавливает слив (очередь сохранится до Ack).
func (r *Runner) drainSpool(ctx context.Context) error {
	for {
		id, data, err := r.spool.Pop()
		if err != nil {
			return nil // очередь пуста — норма
		}
		if err := r.transport.SendInventory(ctx, data); err != nil {
			return err
		}
		if err := r.spool.Ack(id); err != nil {
			return fmt.Errorf("agent: ack %s: %w", id, err)
		}
	}
}

// buildInventory — сбор отчёта и упаковка в конверт NR-024.
func (r *Runner) buildInventory() ([]byte, error) {
	cs := r.Collectors
	if cs == nil {
		cs = collect.DefaultCollectors(collect.NewPowerShellRunner())
	}
	rep := collect.BuildReport(context.Background(), hostname(), cs, r.Now())
	payload, err := json.Marshal(rep)
	if err != nil {
		return nil, fmt.Errorf("agent: отчёт: %w", err)
	}
	env := InventoryEnvelope{
		Kind:        "inventory",
		SchemaVer:   collect.SchemaVersion,
		CollectedAt: r.Now().UTC(),
		Payload:     payload,
	}
	return json.Marshal(env)
}

func (r *Runner) sleep(ctx context.Context, d time.Duration) error {
	if r.Sleep != nil {
		return r.Sleep(ctx, d)
	}
	return defaultSleep(ctx, d)
}

func defaultSleep(ctx context.Context, d time.Duration) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(d):
		return nil
	}
}
