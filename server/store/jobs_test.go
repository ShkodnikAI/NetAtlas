package store

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

// jobFixture — агент, скрипт до статуса signed и задание на него.
func jobFixture(t *testing.T, s *Store) (agentID string, scriptID, versionID int64, jobID int64, sha string) {
	t.Helper()
	ctx := context.Background()
	agentID = "agent:job-test"
	if err := s.UpsertAgent(ctx, agentID, "PC-1", "serial-1", nil, "test"); err != nil {
		t.Fatalf("агент: %v", err)
	}
	scriptID, versionID, sha = createTestScript(t, s, "Скрипт задания")
	pushThroughPipeline(t, s, scriptID, versionID)
	expires := time.Now().Add(24 * time.Hour)
	if _, err := s.SignVersion(ctx, scriptID, versionID, sha, "sig-"+sha, expires, scriptActor); err != nil {
		t.Fatalf("подпись: %v", err)
	}
	jobID, err := s.CreateJob(ctx, CreateJobInput{
		ScriptVersionID: versionID, Targets: []string{agentID},
	}, scriptActor)
	if err != nil {
		t.Fatalf("задание: %v", err)
	}
	return agentID, scriptID, versionID, jobID, sha
}

func TestCreateJobValidation(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	agentID, _, versionID, _, _ := jobFixture(t, s)

	// Не подписанная версия — отказ.
	scriptID2, versionID2, _ := createTestScript(t, s, "Черновик задания")
	if _, err := s.CreateJob(ctx, CreateJobInput{ScriptVersionID: versionID2, Targets: []string{agentID}}, scriptActor); !errors.Is(err, ErrScriptState) {
		t.Fatalf("задание на черновик: %v", err)
	}
	// Цели-пустышки.
	if _, err := s.CreateJob(ctx, CreateJobInput{ScriptVersionID: versionID, Targets: nil}, scriptActor); !errors.Is(err, ErrScriptValue) {
		t.Fatal("задание без целей принято")
	}
	if _, err := s.CreateJob(ctx, CreateJobInput{ScriptVersionID: versionID, Targets: []string{"agent:ghost"}}, scriptActor); !errors.Is(err, ErrNotFound) {
		t.Fatal("неизвестный агент принят")
	}
	// Пилот — ровно один ПК.
	if _, err := s.CreateJob(ctx, CreateJobInput{ScriptVersionID: versionID, Targets: []string{agentID, agentID + "2"}, Pilot: true}, scriptActor); !errors.Is(err, ErrScriptValue) {
		t.Fatal("пилот на две цели принят")
	}
	// Повторная цель.
	if _, err := s.CreateJob(ctx, CreateJobInput{ScriptVersionID: versionID, Targets: []string{agentID, agentID}}, scriptActor); !errors.Is(err, ErrScriptValue) {
		t.Fatal("повторная цель принята")
	}
	_ = scriptID2
}

func TestJobLifecycleAndAutostop(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	agentID, _, _, jobID, _ := jobFixture(t, s)

	// Кандидат выдачи: подписан, в очереди, квота 1 из 1.
	cands, err := s.PendingDispatch(ctx, agentID)
	if err != nil {
		t.Fatalf("кандидаты: %v", err)
	}
	if len(cands) != 1 || cands[0].JobID != jobID {
		t.Fatalf("кандидаты неполны: %+v", cands)
	}
	if cands[0].Total != 1 || cands[0].Delivered != 0 || cands[0].SignedBy != scriptActor {
		t.Fatalf("состояние раскатки: %+v", cands[0])
	}
	// Выдача: queued → sent.
	if err := s.MarkTargetSent(ctx, jobID, agentID, `{"envelope":{}}`); err != nil {
		t.Fatalf("выдача: %v", err)
	}
	// Повторная выдача — отказ (уже sent).
	if err := s.MarkTargetSent(ctx, jobID, agentID, "{}"); !errors.Is(err, ErrScriptState) {
		t.Fatalf("повторная выдача: %v", err)
	}
	// Провал → автостоп: цель failed, задание stopped.
	if _, err := s.RecordJobResult(ctx, jobID, agentID, false, "служба не поднялась", nil, nil, "agent-api"); err != nil {
		t.Fatalf("результат: %v", err)
	}
	job, err := s.JobByID(ctx, jobID)
	if err != nil {
		t.Fatalf("задание: %v", err)
	}
	if job.Status != "stopped" {
		t.Fatalf("статус задания после провала: %q", job.Status)
	}
	if job.Targets[0].State != "failed" {
		t.Fatalf("состояние цели: %q", job.Targets[0].State)
	}
}

func TestJobMetricWorseningStops(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	// Задание с порогом метрики (jobFixture2 задаёт MetricThreshold: 2).
	agentID, _, _, jobID, _ := jobFixture2(t, s)
	if err := s.MarkTargetSent(ctx, jobID, agentID, "{}"); err != nil {
		t.Fatalf("выдача: %v", err)
	}
	// Метрика ухудшилась сверх порога: before 1, after 5, порог 2 → провал.
	b, a := 1.0, 5.0
	if _, err := s.RecordJobResult(ctx, jobID, agentID, true, "готово", &b, &a, "agent-api"); err != nil {
		t.Fatalf("результат с метрикой: %v", err)
	}
	job, _ := s.JobByID(ctx, jobID)
	if job.Status != "stopped" {
		t.Fatalf("ухудшение метрики не остановило задание: %q", job.Status)
	}
	if job.Targets[0].Error == "" {
		t.Fatal("причина ухудшения не записана")
	}
	// В пределах порога — успех: before 1, after 2, порог 2.
	agentID2, _, _, jobID2, _ := jobFixture2(t, s)
	if err := s.MarkTargetSent(ctx, jobID2, agentID2, "{}"); err != nil {
		t.Fatalf("выдача 2: %v", err)
	}
	b2, a2 := 1.0, 2.0
	tgt, err := s.RecordJobResult(ctx, jobID2, agentID2, true, "готово", &b2, &a2, "agent-api")
	if err != nil {
		t.Fatalf("результат в пороге: %v", err)
	}
	if tgt.State != "done" {
		t.Fatalf("успех в пороге записан как %q", tgt.State)
	}
}

// jobFixture2 — второй набор (агент+скрипт+задание с порогом метрики).
func jobFixture2(t *testing.T, s *Store) (string, int64, int64, int64, string) {
	t.Helper()
	ctx := context.Background()
	agentID := "agent:job-test-2"
	if err := s.UpsertAgent(ctx, agentID, "PC-2", "serial-2", nil, "test"); err != nil {
		t.Fatalf("агент: %v", err)
	}
	scriptID, versionID, sha := createTestScript(t, s, "Скрипт задания 2")
	pushThroughPipeline(t, s, scriptID, versionID)
	if _, err := s.SignVersion(ctx, scriptID, versionID, sha, "sig2-"+sha, time.Now().Add(24*time.Hour), scriptActor); err != nil {
		t.Fatalf("подпись: %v", err)
	}
	jobID, err := s.CreateJob(ctx, CreateJobInput{
		ScriptVersionID: versionID, Targets: []string{agentID}, MetricThreshold: 2.0,
	}, scriptActor)
	if err != nil {
		t.Fatalf("задание: %v", err)
	}
	return agentID, scriptID, versionID, jobID, sha
}

func TestPilotResultMarksPilotOK(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	agentID := "agent:pilot-pc"
	if err := s.UpsertAgent(ctx, agentID, "БУХ-02", "serial-3", nil, "test"); err != nil {
		t.Fatalf("агент: %v", err)
	}
	scriptID, versionID, sha := createTestScript(t, s, "Драйвер из пилота")
	// Драйвер: пилот обязателен шлюзом, но store-флаг ставится результатом.
	pushThroughPipeline(t, s, scriptID, versionID)
	if _, err := s.SignVersion(ctx, scriptID, versionID, sha, "sigp", time.Now().Add(24*time.Hour), scriptActor); err != nil {
		t.Fatalf("подпись: %v", err)
	}
	jobID, err := s.CreateJob(ctx, CreateJobInput{ScriptVersionID: versionID, Targets: []string{agentID}, Pilot: true}, scriptActor)
	if err != nil {
		t.Fatalf("пилотное задание: %v", err)
	}
	if err := s.MarkTargetSent(ctx, jobID, agentID, "{}"); err != nil {
		t.Fatalf("выдача: %v", err)
	}
	if _, err := s.RecordJobResult(ctx, jobID, agentID, true, "пилот успешен", nil, nil, "agent-api"); err != nil {
		t.Fatalf("результат: %v", err)
	}
	_, versions, _, _, _ := s.ScriptCard(ctx, scriptID)
	if !versions[0].PilotOK {
		t.Fatal("pilot_ok не отмечен после успешного пилота")
	}
}

func TestStopJobAndQueue(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	agentID, _, _, jobID, _ := jobFixture(t, s)
	// Остановка до выдачи: queued → stopped.
	if err := s.StopJob(ctx, jobID, "передумал", scriptActor); err != nil {
		t.Fatalf("остановка: %v", err)
	}
	cands, _ := s.PendingDispatch(ctx, agentID)
	if len(cands) != 0 {
		t.Fatalf("после остановки кандидат всё ещё выдаётся: %+v", cands)
	}
	// Повторная остановка — отказ.
	if err := s.StopJob(ctx, jobID, "ещё раз", scriptActor); !errors.Is(err, ErrScriptState) {
		t.Fatalf("повторная остановка: %v", err)
	}
}

func TestPendingDispatchExpiryData(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	agentID, _, _, jobID, _ := jobFixture(t, s)
	_ = jobID
	cands, err := s.PendingDispatch(ctx, agentID)
	if err != nil {
		t.Fatalf("кандидаты: %v", err)
	}
	if len(cands) != 1 {
		t.Fatalf("кандидатов %d", len(cands))
	}
	if cands[0].Expires.IsZero() {
		t.Fatal("срок подписи не прочитан: шлюз не сможет проверить expiry")
	}
	if cands[0].Content == "" || cands[0].SHA256 == "" {
		t.Fatal("содержимое и хэш кандидата пусты")
	}
	// Данные для конверта сериализуемы.
	raw, err := json.Marshal(cands[0])
	if err != nil {
		t.Fatalf("кандидат не сериализуется: %v", err)
	}
	if len(raw) == 0 {
		t.Fatal("пустая сериализация")
	}
}

func TestMarkTargetExpiredWritesState(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	agentID, _, _, jobID, _ := jobFixture(t, s)
	if err := s.MarkTargetExpired(ctx, jobID, agentID, "gate: срок подписи истёк"); err != nil {
		t.Fatalf("expired: %v", err)
	}
	job, _ := s.JobByID(ctx, jobID)
	if job.Targets[0].State != "expired" {
		t.Fatalf("цель не помечена expired: %q", job.Targets[0].State)
	}
	cands, _ := s.PendingDispatch(ctx, agentID)
	if len(cands) != 0 {
		t.Fatalf("expired-цель попала в кандидаты: %+v", cands)
	}
}

func TestRecordJobResultWrongState(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	agentID, _, _, jobID, _ := jobFixture(t, s)
	// Результат без выдачи (queued) — отказ.
	if _, err := s.RecordJobResult(ctx, jobID, agentID, true, "рано", nil, nil, "agent-api"); !errors.Is(err, ErrScriptState) {
		t.Fatalf("результат в queued: %v", err)
	}
}
