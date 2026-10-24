// Отправка отчёта проверок безопасности (NR-010): конверт вида
// security/schema 1, ошибка отправки не роняет цикл.
package agent

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/ShkodnikAI/NetAtlas/agent/checks"
)

type fakeSecurityCheck struct {
	name string
	res  checks.Result
	err  error
}

func (f *fakeSecurityCheck) Name() string { return f.name }

func (f *fakeSecurityCheck) Run(_ context.Context) (checks.Result, error) { return f.res, f.err }

// Успешный цикл: отчёт проверок ушёл на /agent/v1/security.
func TestRunOnceSendsSecurity(t *testing.T) {
	tr := &fakeTransport{pollSec: 120}
	r := newTestRunner(t, tr)
	r.SecurityChecks = []checks.Checker{
		&fakeSecurityCheck{name: checks.CheckSMBv1, res: checks.Result{ID: checks.CheckSMBv1, Status: checks.StatusFail, Detail: "SMBv1 включён"}},
	}
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if len(tr.security) != 1 {
		t.Fatalf("отчётов отправлено %d, хочу 1", len(tr.security))
	}
	var env InventoryEnvelope
	if err := json.Unmarshal(tr.security[0], &env); err != nil {
		t.Fatalf("конверт: %v", err)
	}
	if env.Kind != "security" || env.SchemaVer != checks.SchemaVersion {
		t.Fatalf("конверт: kind=%q schema=%d", env.Kind, env.SchemaVer)
	}
	var rep checks.Report
	if err := json.Unmarshal(env.Payload, &rep); err != nil {
		t.Fatalf("payload: %v", err)
	}
	if len(rep.Results) != 1 || rep.Results[0].ID != checks.CheckSMBv1 || rep.Results[0].Status != checks.StatusFail {
		t.Fatalf("результаты: %+v", rep.Results)
	}
}

// Ошибка отправки не роняет цикл: отчёт не в очереди (пересборка в
// следующем цикле), инвентарь отправлен как обычно.
func TestSecuritySendErrorDoesNotBreakCycle(t *testing.T) {
	tr := &fakeTransport{pollSec: 120}
	r := newTestRunner(t, tr)
	r.SecurityChecks = []checks.Checker{
		&fakeSecurityCheck{name: checks.CheckFirewall, res: checks.Result{ID: checks.CheckFirewall, Status: checks.StatusPass}},
	}
	// SendSecurity падает, SendInventory работает: отдельная ошибка.
	tr.secErr = errors.New("agent: security: сеть недоступна")
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("ошибка security уронила цикл: %v", err)
	}
	if len(tr.sent) != 1 {
		t.Fatalf("инвентарь не отправлен: %d", len(tr.sent))
	}
	if len(tr.security) != 0 {
		t.Fatalf("отчёт не должен был уйти: %d", len(tr.security))
	}
}

// Без проверок (nil) отчёт не отправляется: владелец мог отключить
// сбор безопасности флагом конфигурации.
func TestSecurityDisabledByDefaultInTestRunner(t *testing.T) {
	tr := &fakeTransport{pollSec: 120}
	r := newTestRunner(t, tr)
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if len(tr.security) != 0 {
		t.Fatalf("без проверок отчёт не должен уходить: %d", len(tr.security))
	}
}

// Ошибка проверки попадает в отчёт как unknown и отправляется.
func TestSecurityCheckErrorIsUnknown(t *testing.T) {
	tr := &fakeTransport{pollSec: 120}
	r := newTestRunner(t, tr)
	r.SecurityChecks = []checks.Checker{
		&fakeSecurityCheck{name: checks.CheckBitLocker, err: errors.New("powershell: доступ запрещён")},
		&fakeSecurityCheck{name: checks.CheckPorts, res: checks.Result{ID: checks.CheckPorts, Status: checks.StatusPass}},
	}
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	var env InventoryEnvelope
	if err := json.Unmarshal(tr.security[0], &env); err != nil {
		t.Fatalf("конверт: %v", err)
	}
	var rep checks.Report
	if err := json.Unmarshal(env.Payload, &rep); err != nil {
		t.Fatalf("payload: %v", err)
	}
	if len(rep.Results) != 2 {
		t.Fatalf("результатов: %d", len(rep.Results))
	}
	if rep.Results[0].Status != checks.StatusUnknown {
		t.Fatalf("ошибка проверки — unknown, получен %q", rep.Results[0].Status)
	}
	if rep.Results[1].Status != checks.StatusPass {
		t.Fatalf("рабочая проверка пострадала: %+v", rep.Results[1])
	}
	if rep.SecuritySchemaVersion != checks.SchemaVersion {
		t.Fatalf("версия схемы: %d", rep.SecuritySchemaVersion)
	}
	if rep.CollectedAt == "" {
		t.Fatal("время сбора обязательно")
	}
	_ = time.Now
}
