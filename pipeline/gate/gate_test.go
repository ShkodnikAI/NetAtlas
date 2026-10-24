package gate

import (
	"errors"
	"testing"
	"time"
)

// ready — скрипт, прошедший весь конвейер до подписи и подписанный.
func ready() Script {
	return Script{
		Kind:        KindCatalog,
		Category:    CategoryGeneral,
		Status:      StatusSigned,
		SHA256:      "aabbccdd00112233aabbccdd00112233",
		SignedBy:    "owner",
		SignedSHA:   "aabbccdd00112233aabbccdd00112233",
		SignExpires: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
		PilotPassed: false,
	}
}

func job() Job {
	return Job{
		DispatchEnabled:    true,
		AllowCustomScripts: true,
		Target:             "agent:one",
		Targets:            []string{"agent:one", "agent:two"},
	}
}

var now = time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)

// Позитив: всё выполнено — шлюз пропускает.
func TestCanDispatchAllowsReadyScript(t *testing.T) {
	if err := CanDispatch(ready(), job(), now); err != nil {
		t.Fatalf("готовый скрипт отклонён: %v", err)
	}
}

// Негатив 1: неподписанный скрипт отвергается.
func TestCanDispatchRejectsUnsigned(t *testing.T) {
	s := ready()
	s.SignedBy = ""
	if err := CanDispatch(s, job(), now); !errors.Is(err, ErrNotSigned) {
		t.Fatalf("хочу ErrNotSigned, получено %v", err)
	}
}

// Негатив 2: подписан, но статус ниже tested.
func TestCanDispatchRejectsStatusBelowTested(t *testing.T) {
	for _, status := range []string{StatusDraft, StatusChecked} {
		s := ready()
		s.Status = status
		if err := CanDispatch(s, job(), now); !errors.Is(err, ErrStatusTooLow) {
			t.Fatalf("статус %q: хочу ErrStatusTooLow, получено %v", status, err)
		}
	}
}

// Негатив 2б: rejected вне цепочки — тоже ниже tested.
func TestCanDispatchRejectsRejected(t *testing.T) {
	s := ready()
	s.Status = StatusRejected
	if err := CanDispatch(s, job(), now); !errors.Is(err, ErrStatusTooLow) {
		t.Fatalf("rejected: хочу ErrStatusTooLow, получено %v", err)
	}
}

// Негатив 3: изменён после подписи — другой хэш содержимого.
func TestCanDispatchRejectsContentChanged(t *testing.T) {
	s := ready()
	s.SHA256 = "ffffffff00112233aabbccdd00112233"
	if err := CanDispatch(s, job(), now); !errors.Is(err, ErrContentChanged) {
		t.Fatalf("хочу ErrContentChanged, получено %v", err)
	}
}

// Негатив 4: просроченная подпись.
func TestCanDispatchRejectsExpiredSignature(t *testing.T) {
	s := ready()
	s.SignExpires = now.Add(-time.Second)
	if err := CanDispatch(s, job(), now); !errors.Is(err, ErrSignatureExpired) {
		t.Fatalf("хочу ErrSignatureExpired, получено %v", err)
	}
	// Граница: срок равен now — уже истёк (After строго).
	s.SignExpires = now
	if err := CanDispatch(s, job(), now); !errors.Is(err, ErrSignatureExpired) {
		t.Fatalf("срок = now: хочу ErrSignatureExpired, получено %v", err)
	}
}

// Негатив 5: цель вне разрешённого набора.
func TestCanDispatchRejectsForeignTarget(t *testing.T) {
	j := job()
	j.Target = "agent:intruder"
	if err := CanDispatch(ready(), j, now); !errors.Is(err, ErrTargetNotAllowed) {
		t.Fatalf("хочу ErrTargetNotAllowed, получено %v", err)
	}
}

// Негатив 6: драйвер без этапа pilot.
func TestCanDispatchRejectsDriverWithoutPilot(t *testing.T) {
	for _, cat := range []string{CategoryDriver, CategoryNic} {
		s := ready()
		s.Category = cat
		if err := CanDispatch(s, job(), now); !errors.Is(err, ErrPilotRequired) {
			t.Fatalf("категория %q без pilot: хочу ErrPilotRequired, получено %v", cat, err)
		}
		// Пилотное задание (этап «один ПК») — проходит: это и есть пилот.
		j := job()
		j.IsPilot = true
		if err := CanDispatch(s, j, now); err != nil {
			t.Fatalf("категория %q, пилотное задание: %v", cat, err)
		}
		// После пройденного пилота — обычное задание тоже проходит.
		s.PilotPassed = true
		if err := CanDispatch(s, job(), now); err != nil {
			t.Fatalf("категория %q с pilot: %v", cat, err)
		}
	}
}

// Негатив 7: kind=script при выключенном allow_custom_scripts.
func TestCanDispatchRejectsCustomScriptsDisabled(t *testing.T) {
	s := ready()
	s.Kind = KindScript
	j := job()
	j.AllowCustomScripts = false
	if err := CanDispatch(s, j, now); !errors.Is(err, ErrCustomScriptsDisabled) {
		t.Fatalf("хочу ErrCustomScriptsDisabled, получено %v", err)
	}
	// catalog при том же конфиге проходит.
	s.Kind = KindCatalog
	if err := CanDispatch(s, j, now); err != nil {
		t.Fatalf("catalog при выключенных произвольных: %v", err)
	}
}

// Негатив 8: диспетчеризация выключена на сервере.
func TestCanDispatchRejectsDispatchDisabled(t *testing.T) {
	j := job()
	j.DispatchEnabled = false
	if err := CanDispatch(ready(), j, now); !errors.Is(err, ErrDispatchDisabled) {
		t.Fatalf("хочу ErrDispatchDisabled, получено %v", err)
	}
}

// Порядок политики: переключатели сервера сильнее состояния скрипта.
func TestPolicyBeforeScriptState(t *testing.T) {
	s := ready()
	s.Status = StatusDraft // и статус низкий, и dispatch выключен
	j := job()
	j.DispatchEnabled = false
	if err := CanDispatch(s, j, now); !errors.Is(err, ErrDispatchDisabled) {
		t.Fatalf("первой должна быть политика сервера: %v", err)
	}
}

// --- цепочка статусов -------------------------------------------------------

func TestCanAdvanceOnlyForward(t *testing.T) {
	// Каждый шаг цепочки разрешён.
	for i := 0; i < len(chain)-1; i++ {
		if err := CanAdvance(chain[i], chain[i+1]); err != nil {
			t.Fatalf("шаг %s → %s: %v", chain[i], chain[i+1], err)
		}
	}
	// Пропуск шагов запрещён.
	if err := CanAdvance(StatusDraft, StatusTested); err == nil {
		t.Fatal("draft → tested: пропуск шага не отвергнут")
	}
	if err := CanAdvance(StatusDraft, StatusReleased); err == nil {
		t.Fatal("draft → released: пропуск шагов не отвергнут")
	}
	// Назад запрещено, кроме rejected.
	if err := CanAdvance(StatusChecked, StatusDraft); err == nil {
		t.Fatal("назад к draft не отвергнут")
	}
	if err := CanAdvance(StatusReleased, StatusSigned); err == nil {
		t.Fatal("назад к signed не отвергнут")
	}
	if err := CanAdvance(StatusTested, StatusRejected); err != nil {
		t.Fatalf("rejected — единственный обратный: %v", err)
	}
	// Из rejected переходов нет.
	if err := CanAdvance(StatusRejected, StatusDraft); err == nil {
		t.Fatal("возврат из rejected не отвергнут")
	}
	if err := CanAdvance(StatusRejected, StatusRejected); err == nil {
		t.Fatal("rejected → rejected не отвергнут")
	}
	// Неизвестные статусы.
	if err := CanAdvance("nope", StatusDraft); err == nil {
		t.Fatal("неизвестный from не отвергнут")
	}
	if err := CanAdvance(StatusDraft, "nope"); err == nil {
		t.Fatal("неизвестный to не отвергнут")
	}
	// released — конец цепочки.
	if _, err := Next(StatusReleased); err == nil {
		t.Fatal("у released не может быть следующего")
	}
}

func TestAtLeast(t *testing.T) {
	if !AtLeast(StatusTested, StatusTested) {
		t.Fatal("tested >= tested")
	}
	if !AtLeast(StatusReleased, StatusTested) {
		t.Fatal("released >= tested")
	}
	if AtLeast(StatusChecked, StatusTested) {
		t.Fatal("checked < tested")
	}
	if AtLeast(StatusRejected, StatusDraft) {
		t.Fatal("rejected ниже всего")
	}
	if AtLeast("nope", StatusDraft) {
		t.Fatal("неизвестный статус не проходит")
	}
}

// --- раскатка группами ------------------------------------------------------

func TestQuota(t *testing.T) {
	cases := []struct {
		total, done, want int
	}{
		{0, 0, 0},   // целей нет
		{1, 0, 1},   // одна цель — сразу её
		{1, 1, 1},   // успех — больше некому
		{10, 0, 1},  // сначала один ПК
		{10, 1, 2},  // успех первого открывает группу 2 (10 % = 1 машина)
		{10, 2, 10}, // группа 2 успешна — остальные
		{20, 0, 1},
		{20, 1, 3},  // группа 2: 1 + 10 % от 20 = 3
		{20, 2, 3},  // группа 2 ещё не вся успешна
		{20, 3, 20}, // группа 2 успешна — остальные
		{3, 0, 1},
		{3, 1, 2}, // ceil(0.3) = 1
		{3, 2, 3},
	}
	for _, c := range cases {
		if got := Quota(c.total, c.done); got != c.want {
			t.Errorf("Quota(%d, %d) = %d, хочу %d", c.total, c.done, got, c.want)
		}
	}
}
