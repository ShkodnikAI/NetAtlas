// Тесты исполнителя заданий (NR-025): все негативные сценарии из
// наряда — агент не запускает неподписанное, с неверной подписью,
// изменённое, просроченное, чужое, повторное (после перезапуска),
// при exec_enabled=false, второе при работающем первом, превышение
// размера. Подставной раннер проверяет, что в процесс попадает ровно
// проверенное содержимое.
package exec

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ShkodnikAI/NetAtlas/agent/verify"
	"github.com/ShkodnikAI/NetAtlas/server/signing"
)

const selfID = "agent:test-agent"

// harness — ключи, seen, раннер-шпион, снапшоттер-фейк, журнал.
type harness struct {
	t       *testing.T
	pub     ed25519.PublicKey
	priv    ed25519.PrivateKey
	deps    *Deps
	runner  *fakeRunner
	snap    *fakeSnap
	log     *memLog
	seen    *verify.FileSeen
	dir     string
	enabled *bool
}

type fakeRunner struct {
	mu      sync.Mutex
	got     []string
	delay   time.Duration
	code    int
	output  []byte
	err     error
	started chan struct{}
}

func (r *fakeRunner) Run(ctx context.Context, script string, timeout time.Duration) (int, []byte, error) {
	r.mu.Lock()
	r.got = append(r.got, script)
	r.mu.Unlock()
	if r.started != nil {
		r.started <- struct{}{}
	}
	if r.delay > 0 {
		select {
		case <-ctx.Done():
			return 0, nil, ctx.Err()
		case <-time.After(r.delay):
		}
	}
	return r.code, r.output, r.err
}

func (r *fakeRunner) scripts() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.got...)
}

type fakeSnap struct {
	checkpoints []int64
	reads       int
	value       float64
}

func (s *fakeSnap) Checkpoint(_ context.Context, jobID int64) error {
	s.checkpoints = append(s.checkpoints, jobID)
	return nil
}

func (s *fakeSnap) Measure(context.Context) (*float64, error) {
	s.reads++
	v := s.value
	return &v, nil
}

type memLog struct {
	mu    sync.Mutex
	lines []string
}

func (m *memLog) Logf(format string, args ...any) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lines = append(m.lines, fmt.Sprintf(format, args...))
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	dir := t.TempDir()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	seen, err := verify.NewFileSeen(filepath.Join(dir, "exec_seen.txt"))
	if err != nil {
		t.Fatalf("seen: %v", err)
	}
	t.Cleanup(func() { seen.Close() })
	log := &memLog{}
	runner := &fakeRunner{}
	snap := &fakeSnap{}
	on := true
	deps, err := NewDeps(func() bool { return on }, pub, selfID, seen, snap, runner, log)
	if err != nil {
		t.Fatalf("deps: %v", err)
	}
	deps.Now = func() time.Time { return time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC) }
	return &harness{t: t, pub: pub, priv: priv, deps: deps, runner: runner, snap: snap, log: log, seen: seen, dir: dir, enabled: &on}
}

// signedJob — подписанное задание: содержимое покрыто подписью.
func (h *harness) signedJob(jobID int64, content string, expires time.Time) AgentJob {
	h.t.Helper()
	nonce := make([]byte, signing.NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		h.t.Fatalf("nonce: %v", err)
	}
	issued := h.deps.Now().Add(-time.Minute)
	if !expires.After(issued) {
		// Просроченное задание подписывается корректно: выпущено
		// раньше и уже истекло (expires после issued, оба в прошлом).
		issued = expires.Add(-time.Hour)
	}
	env := signing.Envelope{
		JobID:         fmt.Sprintf("job:%d:%s", jobID, selfID),
		AgentID:       selfID,
		Kind:          "catalog",
		ContentSHA256: signing.HashContent([]byte(content)),
		IssuedAt:      issued,
		ExpiresAt:     expires,
		Nonce:         nonce,
	}
	sig, err := signing.Sign(env, h.priv)
	if err != nil {
		h.t.Fatalf("подпись: %v", err)
	}
	return AgentJob{
		JobID:     jobID,
		Name:      "Тестовое задание",
		Kind:      "catalog",
		Content:   content,
		Envelope:  env,
		Signature: base64Of(sig.Signature),
		ExpiresAt: expires.UTC().Format(time.RFC3339),
	}
}

func base64Of(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

// Полный цикл: включённое исполнение, подписанное задание.
func TestProcessRunsVerifiedJob(t *testing.T) {
	h := newHarness(t)
	content := "Write-Output 'netatlas-smoke'"
	job := h.signedJob(1, content, h.deps.Now().Add(24*time.Hour))
	h.runner.output = []byte("netatlas-smoke")

	out := Process(context.Background(), job, h.deps)
	if !out.OK || !out.Executed {
		t.Fatalf("задание не исполнено: %+v", out)
	}
	got := h.runner.scripts()
	if len(got) != 1 || got[0] != content {
		t.Fatalf("в процесс попало не то содержимое: %q", got)
	}
	if !strings.Contains(out.Detail, "код возврата 0") {
		t.Fatalf("detail: %q", out.Detail)
	}
	// В журнале есть запись запуска.
	joined := strings.Join(h.log.lines, "\n")
	if !strings.Contains(joined, "job 1: запуск") {
		t.Fatalf("журнал без запуска: %v", h.log.lines)
	}
}

// exec_enabled=false: ничего не запускается, причина серверу.
func TestProcessDisabledByPolicy(t *testing.T) {
	h := newHarness(t)
	*h.enabled = false
	job := h.signedJob(1, "Write-Output x", h.deps.Now().Add(24*time.Hour))

	out := Process(context.Background(), job, h.deps)
	if out.Executed {
		t.Fatal("запуск при выключенном исполнении")
	}
	if out.OK || !strings.Contains(out.Detail, "исполнение выключено") {
		t.Fatalf("причина не серверу: %+v", out)
	}
	if len(h.runner.scripts()) != 0 {
		t.Fatal("раннер вызван при выключенном исполнении")
	}
}

// Политика читается на каждое задание: владелец включил — работает.
func TestPolicyReadPerJob(t *testing.T) {
	h := newHarness(t)
	dir := h.dir
	if err := WriteConfig(dir, ExecConfig{ExecEnabled: false}); err != nil {
		t.Fatalf("запись политики: %v", err)
	}
	if LoadConfig(dir).ExecEnabled {
		t.Fatal("политика по умолчанию должна быть выключена")
	}
	if err := WriteConfig(dir, ExecConfig{ExecEnabled: true}); err != nil {
		t.Fatalf("включение: %v", err)
	}
	if !LoadConfig(dir).ExecEnabled {
		t.Fatal("политика не прочиталась")
	}
	// Битый файл — выключено (не паника).
	if err := WriteConfig(dir, ExecConfig{ExecEnabled: true}); err != nil {
		t.Fatalf("запись: %v", err)
	}
	if err := writeFile(filepath.Join(dir, ConfigFileName), []byte("{битый")); err != nil {
		t.Fatalf("битый файл: %v", err)
	}
	if LoadConfig(dir).ExecEnabled {
		t.Fatal("битая политика должна означать выключено")
	}
}

// Неподписанное, с неверной подписью, изменённое, просроченное,
// чужое — ни одно не запускается (негативы 1–5).
func TestProcessRejectsUnverified(t *testing.T) {
	t.Run("нет подписи", func(t *testing.T) {
		h := newHarness(t)
		job := h.signedJob(1, "Write-Output x", h.deps.Now().Add(time.Hour))
		job.Signature = ""
		out := Process(context.Background(), job, h.deps)
		if out.Executed || out.OK || !strings.Contains(out.Detail, "подпись") {
			t.Fatalf("неподписанное прошло: %+v", out)
		}
	})
	t.Run("неверная подпись", func(t *testing.T) {
		h := newHarness(t)
		job := h.signedJob(1, "Write-Output x", h.deps.Now().Add(time.Hour))
		other := make([]byte, len(job.Envelope.Nonce))
		job.Envelope.Nonce = other // конверт изменился — подпись не сходится
		out := Process(context.Background(), job, h.deps)
		if out.Executed || out.OK || !strings.Contains(out.Detail, "подпись") {
			t.Fatalf("неверная подпись прошла: %+v", out)
		}
	})
	t.Run("изменённое содержимое", func(t *testing.T) {
		h := newHarness(t)
		job := h.signedJob(1, "Write-Output x", h.deps.Now().Add(time.Hour))
		job.Content = "Remove-Item C:\\ -Recurse" // подмена после подписи
		out := Process(context.Background(), job, h.deps)
		if out.Executed || out.OK || !strings.Contains(out.Detail, "содержимое") {
			t.Fatalf("изменённое прошло: %+v", out)
		}
	})
	t.Run("просроченное", func(t *testing.T) {
		h := newHarness(t)
		job := h.signedJob(1, "Write-Output x", h.deps.Now().Add(-time.Hour))
		out := Process(context.Background(), job, h.deps)
		if out.Executed || out.OK || !strings.Contains(out.Detail, "просрочено") {
			t.Fatalf("просроченное прошло: %+v", out)
		}
	})
	t.Run("чужое по цели", func(t *testing.T) {
		h := newHarness(t)
		job := h.signedJob(1, "Write-Output x", h.deps.Now().Add(time.Hour))
		job.Envelope.AgentID = "agent:other" // конверт чужой — подпись не сходится
		out := Process(context.Background(), job, h.deps)
		if out.Executed || out.OK {
			t.Fatalf("чужое прошло: %+v", out)
		}
	})
}

// Повторное задание не запускается и после перезапуска агента
// (негатив 6): новый исполнитель с тем же файлом seen.
func TestProcessRejectsReplayAfterRestart(t *testing.T) {
	h := newHarness(t)
	job := h.signedJob(1, "Write-Output x", h.deps.Now().Add(time.Hour))
	if out := Process(context.Background(), job, h.deps); !out.OK {
		t.Fatalf("первый прогон не удался: %+v", out)
	}
	// «Перезапуск»: новый seen из того же файла, новый deps.
	seen2, err := verify.NewFileSeen(filepath.Join(h.dir, "exec_seen.txt"))
	if err != nil {
		t.Fatalf("seen2: %v", err)
	}
	t.Cleanup(func() { seen2.Close() })
	deps2, err := NewDeps(h.deps.Enabled, h.pub, selfID, seen2, h.snap, h.runner, h.log)
	if err != nil {
		t.Fatalf("deps2: %v", err)
	}
	deps2.Now = h.deps.Now
	out := Process(context.Background(), job, deps2)
	if out.Executed || out.OK || !strings.Contains(out.Detail, "повтор") {
		t.Fatalf("повтор после перезапуска прошёл: %+v", out)
	}
}

// Второе задание при работающем первом не запускается (негатив 8).
func TestProcessRejectsConcurrent(t *testing.T) {
	h := newHarness(t)
	h.runner.delay = 300 * time.Millisecond
	h.runner.started = make(chan struct{}, 2)
	j1 := h.signedJob(1, "Write-Output one", h.deps.Now().Add(time.Hour))
	j2 := h.signedJob(2, "Write-Output two", h.deps.Now().Add(time.Hour))

	done := make(chan Outcome, 1)
	go func() { done <- Process(context.Background(), j1, h.deps) }()
	<-h.runner.started // первое начало исполняться
	out := Process(context.Background(), j2, h.deps)
	if out.Executed || out.OK || !strings.Contains(out.Detail, "занят") {
		t.Fatalf("второе задание прошло при работающем первом: %+v", out)
	}
	if o := <-done; !o.OK {
		t.Fatalf("первое задание сломалось: %+v", o)
	}
}

// Превышение лимита размера не запускается (негатив 9).
func TestProcessRejectsOversize(t *testing.T) {
	h := newHarness(t)
	big := "#" + strings.Repeat("a", MaxScriptBytes+1)
	job := h.signedJob(1, big, h.deps.Now().Add(time.Hour))
	out := Process(context.Background(), job, h.deps)
	if out.Executed || out.OK || !strings.Contains(out.Detail, "лимит") {
		t.Fatalf("переразмерное прошло: %+v", out)
	}
}

// Изменяющее задание: точка восстановления и метрики до/после.
func TestProcessChangesSystem(t *testing.T) {
	h := newHarness(t)
	job := h.signedJob(7, "Write-Output x", h.deps.Now().Add(time.Hour))
	job.ChangesSystem = true
	h.snap.value = 42.5

	out := Process(context.Background(), job, h.deps)
	if !out.OK {
		t.Fatalf("задание не исполнено: %+v", out)
	}
	if len(h.snap.checkpoints) != 1 || h.snap.checkpoints[0] != 7 {
		t.Fatalf("точка восстановления не создана: %v", h.snap.checkpoints)
	}
	if h.snap.reads != 2 {
		t.Fatalf("метрик снято %d, хочу 2 (до и после)", h.snap.reads)
	}
	if out.MetricBefore == nil || *out.MetricBefore != 42.5 || out.MetricAfter == nil {
		t.Fatalf("метрики не в результате: %+v", out)
	}
}

// Читающее задание: снапшот не нужен.
func TestProcessReadOnlySkipsSnapshot(t *testing.T) {
	h := newHarness(t)
	job := h.signedJob(8, "Write-Output x", h.deps.Now().Add(time.Hour))
	Process(context.Background(), job, h.deps)
	if len(h.snap.checkpoints) != 0 || h.snap.reads != 0 {
		t.Fatalf("читающее задание трогало снапшоты: %v / %d", h.snap.checkpoints, h.snap.reads)
	}
}

// JSON-упаковка: скрипт отката внутри того же конверта.
func TestProcessUnpacksRollback(t *testing.T) {
	h := newHarness(t)
	packed := `{"script":"Write-Output main","rollback_script":"Write-Output rollback"}`
	job := h.signedJob(9, packed, h.deps.Now().Add(time.Hour))
	job.Kind = "script"
	out := Process(context.Background(), job, h.deps)
	if !out.OK {
		t.Fatalf("упакованное не исполнено: %+v", out)
	}
	got := h.runner.scripts()
	if len(got) != 1 || got[0] != "Write-Output main" {
		t.Fatalf("исполнился не основной скрипт: %q", got)
	}
}

// Таймаут: по умолчанию 5 минут, не больше 30 и не больше остатка
// срока действия.
func TestJobTimeout(t *testing.T) {
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	job := AgentJob{}
	if got := job.timeout(now); got != DefaultTimeout {
		t.Fatalf("дефолт: %s", got)
	}
	job.ExpiresAt = now.Add(24 * time.Hour).Format(time.RFC3339)
	if got := job.timeout(now); got != DefaultTimeout {
		t.Fatalf("длинный срок: %s", got)
	}
	// Окно 45 минут шире дефолта: таймаут остаётся 5 минут (конверт
	// только сужает; верхний предел 30 — страховка от будущих источников).
	job.ExpiresAt = now.Add(45 * time.Minute).Format(time.RFC3339)
	if got := job.timeout(now); got != DefaultTimeout {
		t.Fatalf("окно 45 мин: таймаут остаётся дефолтным: %s", got)
	}
	job.ExpiresAt = now.Add(90 * time.Second).Format(time.RFC3339)
	if got := job.timeout(now); got != 90*time.Second {
		t.Fatalf("окно 90 с: %s", got)
	}
	job.ExpiresAt = now.Add(-time.Minute).Format(time.RFC3339)
	if got := job.timeout(now); got != time.Second {
		t.Fatalf("истёкший срок даёт минимальный таймаут: %s", got)
	}
}

// Сбой запуска и код возврата — результат ok=false с причиной.
func TestProcessRunFailures(t *testing.T) {
	t.Run("код возврата не ноль", func(t *testing.T) {
		h := newHarness(t)
		h.runner.code = 3
		job := h.signedJob(1, "exit 3", h.deps.Now().Add(time.Hour))
		out := Process(context.Background(), job, h.deps)
		if out.OK || !strings.Contains(out.Detail, "код возврата 3") {
			t.Fatalf("код возврата потерян: %+v", out)
		}
	})
	t.Run("запуск не состоялся", func(t *testing.T) {
		h := newHarness(t)
		h.runner.err = errors.New("powershell пропал")
		job := h.signedJob(1, "x", h.deps.Now().Add(time.Hour))
		out := Process(context.Background(), job, h.deps)
		if out.OK || !strings.Contains(out.Detail, "не состоялся") {
			t.Fatalf("сбой запуска не виден: %+v", out)
		}
	})
}

func writeFile(path string, data []byte) error {
	return os.WriteFile(path, data, 0o600)
}
