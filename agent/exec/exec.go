// Package exec — исполнение заданий на агенте (NR-025): агент
// получает задание из checkin, сам проверяет подпись независимо от
// сервера (agent/verify: подпись, цель, срок, повтор, хэш) и
// выполняет только разрешённое. Исполнение выключено по умолчанию:
// без локального файла конфигурации exec_enabled агент отвечает
// серверу «исполнение выключено» и ничего не запускает; в коде нет
// способа включить это неявно.
//
// Гарантии пакета: перед запуском всегда verify.Verify; содержимое
// берётся только из подписанного конверта; запуск строго
// последовательный (второе задание при работающем первом не
// запускается); таймаут по умолчанию 5 минут и никогда не больше
// 30; вывод ограничен 256 КБ; любой отказ — причина серверу и
// локальный журнал.
package exec

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/ShkodnikAI/NetAtlas/agent/verify"
	"github.com/ShkodnikAI/NetAtlas/server/signing"
)

// Границы исполнения (наряд NR-025).
const (
	// DefaultTimeout — таймаут задания по умолчанию.
	DefaultTimeout = 5 * time.Minute
	// MaxTimeout — верхний предел таймаута, из конверта не больше.
	MaxTimeout = 30 * time.Minute
	// MaxOutputBytes — предел вывода задания.
	MaxOutputBytes = 256 << 10
	// MaxScriptBytes — предел содержимого задания на агенте.
	MaxScriptBytes = 256 << 10
)

// AgentJob — задание из ответа checkin (совпадает с jobPayload
// сервера). Подпись покрывает только конверт: Content проверяется по
// хэшу; ChangesSystem — подсказка снять точку восстановления, она
// не покрыта подписью и используется только как «лучше снять лишний
// снапшот», никогда наоборот.
type AgentJob struct {
	JobID         int64            `json:"job_id"`
	Name          string           `json:"name"`
	Kind          string           `json:"kind"`
	Content       string           `json:"content"`
	Envelope      signing.Envelope `json:"envelope"`
	Signature     string           `json:"signature"`
	ExpiresAt     string           `json:"expires_at"`
	ChangesSystem bool             `json:"changes_system"`
}

// Outcome — итог обработки задания агентом: что сообщить серверу.
type Outcome struct {
	JobID        int64    `json:"-"`
	Executed     bool     `json:"-"` // запускался ли скрипт
	OK           bool     `json:"ok"`
	Detail       string   `json:"detail"`
	MetricBefore *float64 `json:"metric_before,omitempty"`
	MetricAfter  *float64 `json:"metric_after,omitempty"`
}

// ErrDisabled — исполнение выключено на агенте (политика, не сбой).
var ErrDisabled = errors.New("exec: исполнение выключено на агенте (exec_enabled)")

// ErrBusy — агент уже исполняет другое задание: параллельно ничего
// не запускается.
var ErrBusy = errors.New("exec: агент занят другим заданием")

// ErrTooLarge — содержимое задания превышает лимит размера.
var ErrTooLarge = errors.New("exec: скрипт превышает лимит размера")

// ScriptRunner — запуск проверенного содержимого. Реализация
// обязана исполнять ровно переданную строку (это проверяется
// тестами с подставным раннером).
type ScriptRunner interface {
	Run(ctx context.Context, script string, timeout time.Duration) (code int, output []byte, err error)
}

// Snapshotter — точка восстановления и метрика «до/после».
type Snapshotter interface {
	// Checkpoint создаёт точку восстановления для изменяющего
	// задания; если ОС этого не позволяет, ошибка записывается в
	// журнал, задание не отменяет (наряд: «если ОС это позволяет»).
	Checkpoint(ctx context.Context, jobID int64) error
	// Measure снимает метрику «до» и «после» (nil — нет данных).
	Measure(ctx context.Context) (*float64, error)
}

// ExecLogger — локальный журнал исполнений (без секретов: только
// метаданные — идентификаторы, решения, коды возврата).
type ExecLogger interface {
	Logf(format string, args ...any)
}

// Deps — зависимости исполнителя: политика, ключ проверки, журнал
// увиденных заданий (verify), снапшоттер, раннер, журнал.
type Deps struct {
	// Enabled — политика исполнения: локальный конфиг владельца.
	// Читается на каждое задание: владелец может включить/выключить
	// без перезапуска агента.
	Enabled func() bool
	PubKey  ed25519.PublicKey
	SelfID  string
	Seen    verify.SeenStore
	Snap    Snapshotter
	Runner  ScriptRunner
	Log     ExecLogger
	// Now — точка времени (подменяется в тестах).
	Now func() time.Time

	mu sync.Mutex // последовательность: второе задание при работающем первом — ErrBusy
}

// NewDeps собирает зависимости с проверкой обязательных частей.
func NewDeps(enabled func() bool, pub ed25519.PublicKey, selfID string, seen verify.SeenStore, snap Snapshotter, runner ScriptRunner, log ExecLogger) (*Deps, error) {
	if enabled == nil {
		return nil, errors.New("exec: политика исполнения не задана")
	}
	if len(pub) != ed25519.PublicKeySize {
		return nil, errors.New("exec: ключ проверки подписи не задан")
	}
	if seen == nil {
		return nil, errors.New("exec: журнал увиденных заданий не задан")
	}
	if runner == nil {
		return nil, errors.New("exec: раннер не задан")
	}
	if log == nil {
		return nil, errors.New("exec: журнал исполнений не задан")
	}
	return &Deps{
		Enabled: enabled, PubKey: pub, SelfID: selfID, Seen: seen,
		Snap: snap, Runner: runner, Log: log, Now: time.Now,
	}, nil
}

// packedContent — JSON-упаковка изменяющего задания: основной скрипт
// и подписанный скрипт отката внутри того же конверта (оба покрыты
// одной подписью — хэшем содержимого).
type packedContent struct {
	Script         string `json:"script"`
	RollbackScript string `json:"rollback_script,omitempty"`
}

// unpack — содержимое задания: либо голый PowerShell, либо JSON-
// упаковка со скриптом отката. Возвращает исполняемый скрипт и
// скрипт отката (пусто — нет).
func unpack(kind, content string) (script, rollback string, err error) {
	if kind != "script" {
		return content, "", nil // каталог: голый PowerShell
	}
	var packed packedContent
	if json.Unmarshal([]byte(content), &packed) == nil && packed.Script != "" {
		return packed.Script, packed.RollbackScript, nil
	}
	return content, "", nil
}

// Process — полный путь задания: политика → проверка подписи →
// лимиты → снапшот → запуск → метрики → результат. Любой отказ:
// скрипт не запускается, причина уходит серверу (Outcome) и в
// локальный журнал.
func Process(ctx context.Context, job AgentJob, d *Deps) Outcome {
	if d == nil {
		return Outcome{JobID: job.JobID, Detail: "exec: исполнитель не настроен"}
	}
	// Строгая последовательность: второе задание при работающем
	// первом не ждёт в очереди, а отклоняется (наряд: ничего не
	// запускается параллельно с другим заданием).
	if !d.mu.TryLock() {
		d.Logf("job %d: отказ: агент занят другим заданием", job.JobID)
		return Outcome{JobID: job.JobID, OK: false, Detail: ErrBusy.Error()}
	}
	defer d.mu.Unlock()

	if !d.Enabled() {
		d.Logf("job %d: отказ: исполнение выключено", job.JobID)
		return Outcome{JobID: job.JobID, OK: false, Detail: ErrDisabled.Error()}
	}
	sj, err := job.toSigned()
	if err != nil {
		d.Logf("job %d: отказ: задание не разбирается: %v", job.JobID, err)
		return Outcome{JobID: job.JobID, OK: false, Detail: err.Error()}
	}
	if err := verify.Verify(sj, d.PubKey, d.SelfID, d.Now(), d.Seen); err != nil {
		d.Logf("job %d: отказ проверки: %v", job.JobID, err)
		return Outcome{JobID: job.JobID, OK: false, Detail: err.Error()}
	}
	script, rollback, err := unpack(job.Kind, job.Content)
	if err != nil {
		d.Logf("job %d: отказ: %v", job.JobID, err)
		return Outcome{JobID: job.JobID, OK: false, Detail: err.Error()}
	}
	if len(script) == 0 {
		d.Logf("job %d: отказ: пустое содержимое", job.JobID)
		return Outcome{JobID: job.JobID, OK: false, Detail: "exec: пустое содержимое задания"}
	}
	if len(script) > MaxScriptBytes {
		d.Logf("job %d: отказ: скрипт %d байт больше лимита", job.JobID, len(script))
		return Outcome{JobID: job.JobID, OK: false, Detail: ErrTooLarge.Error()}
	}
	if rollback != "" && len(rollback) > MaxScriptBytes {
		d.Logf("job %d: отказ: скрипт отката больше лимита", job.JobID)
		return Outcome{JobID: job.JobID, OK: false, Detail: ErrTooLarge.Error()}
	}

	timeout := job.timeout(d.Now())
	d.Logf("job %d: запуск (таймаут %s, changes_system=%v)", job.JobID, timeout, job.ChangesSystem)

	var before *float64
	if job.ChangesSystem && d.Snap != nil {
		if err := d.Snap.Checkpoint(ctx, job.JobID); err != nil {
			// Точка восстановления — best effort: ОС может не уметь.
			d.Logf("job %d: точка восстановления: %v", job.JobID, err)
		}
		if m, err := d.Snap.Measure(ctx); err != nil {
			d.Logf("job %d: метрика «до»: %v", job.JobID, err)
		} else {
			before = m
		}
	}

	code, output, runErr := d.Runner.Run(ctx, script, timeout)
	after := d.measureAfter(job, ctx)

	outcome := Outcome{JobID: job.JobID, Executed: true, MetricBefore: before, MetricAfter: after}
	switch {
	case runErr != nil:
		outcome.Detail = fmt.Sprintf("exec: запуск не состоялся: %v", runErr)
	case code != 0:
		outcome.Detail = fmt.Sprintf("exec: код возврата %d, вывод %d байт", code, len(output))
	default:
		outcome.OK = true
		outcome.Detail = fmt.Sprintf("exec: код возврата 0, вывод %d байт", len(output))
	}
	d.Logf("job %d: итог: %s", job.JobID, outcome.Detail)
	return outcome
}

// measureAfter — метрика «после» для изменяющих заданий; ошибка не
// влияет на результат, метрика nil.
func (d *Deps) measureAfter(job AgentJob, ctx context.Context) *float64 {
	if !job.ChangesSystem || d.Snap == nil {
		return nil
	}
	m, err := d.Snap.Measure(ctx)
	if err != nil {
		d.Logf("job %d: метрика «после»: %v", job.JobID, err)
		return nil
	}
	return m
}

// toSigned — конверт задания из ответа checkin: подпись base64,
// содержимое — только из конверта (не из других полей).
func (job AgentJob) toSigned() (signing.SignedJob, error) {
	sig, err := base64.StdEncoding.DecodeString(job.Signature)
	if err != nil || len(sig) == 0 {
		return signing.SignedJob{}, errors.New("exec: подпись задания не разбирается")
	}
	if job.Envelope.JobID == "" {
		return signing.SignedJob{}, errors.New("exec: конверт без job_id")
	}
	return signing.SignedJob{
		Envelope:  job.Envelope,
		Signature: sig,
		Content:   []byte(job.Content),
	}, nil
}

// Logf — запись в журнал исполнителя (nil-журнал безопасен: Process
// проверяет NewDeps, тестовые конструкторы задают Log всегда).
func (d *Deps) Logf(format string, args ...any) {
	if d.Log != nil {
		d.Log.Logf(format, args...)
	}
}

// timeout — таймаут задания: по умолчанию 5 минут, никогда не
// больше 30 (из конверта) и не больше остатка срока действия.
func (job AgentJob) timeout(now time.Time) time.Duration {
	timeout := DefaultTimeout
	if exp, err := time.Parse(time.RFC3339, job.ExpiresAt); err == nil {
		if left := exp.Sub(now); left < timeout {
			timeout = left
		}
	}
	if timeout > MaxTimeout {
		timeout = MaxTimeout
	}
	if timeout <= 0 {
		timeout = time.Second
	}
	return timeout
}
