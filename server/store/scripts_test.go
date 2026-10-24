package store

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ShkodnikAI/NetAtlas/pipeline/gate"
	"github.com/ShkodnikAI/NetAtlas/server/signing"
)

// scriptActor — актор владельческих действий в тестах.
const scriptActor = "owner"

// createTestScript — скрипт-помощник: kind=script, категория general.
func createTestScript(t *testing.T, s *Store, name string) (int64, int64, string) {
	t.Helper()
	scriptID, versionID, err := s.CreateScript(context.Background(), CreateScriptInput{
		Name: name, Kind: gate.KindScript, Category: gate.CategoryGeneral,
		Content: "# тестовый скрипт\nWrite-Output hi\n",
	}, scriptActor)
	if err != nil {
		t.Fatalf("создание скрипта: %v", err)
	}
	v, err := s.VersionContent(context.Background(), scriptID, versionID)
	if err != nil {
		t.Fatalf("версия: %v", err)
	}
	return scriptID, versionID, v.SHA256
}

// pushThroughPipeline — доводит версию до статуса tested.
func pushThroughPipeline(t *testing.T, s *Store, scriptID, versionID int64) {
	t.Helper()
	ctx := context.Background()
	if _, err := s.RecordCheck(ctx, scriptID, versionID, CheckRow{Kind: "static", Source: "stand", Actor: "stand", Result: "pass"}, true); err != nil {
		t.Fatalf("static pass: %v", err)
	}
	if _, err := s.RecordCheck(ctx, scriptID, versionID, CheckRow{Kind: "vm", Source: "stand", Actor: "stand", Result: "pass"}, true); err != nil {
		t.Fatalf("vm pass: %v", err)
	}
}

func TestCreateScriptDraftFromText(t *testing.T) {
	s := openTest(t)
	scriptID, versionID, sha := createTestScript(t, s, "Диагностика адаптера")
	card, versions, checks, sigs, err := s.ScriptCard(context.Background(), scriptID)
	if err != nil {
		t.Fatalf("карточка: %v", err)
	}
	if card.Name != "Диагностика адаптера" || card.Kind != gate.KindScript || card.Category != gate.CategoryGeneral {
		t.Fatalf("карточка неполна: %+v", card)
	}
	if len(versions) != 1 || versions[0].Status != gate.StatusDraft {
		t.Fatalf("версия 1 должна быть draft: %+v", versions)
	}
	if versions[0].SHA256 != sha {
		t.Fatal("хэш версии не совпадает")
	}
	if len(checks[versionID]) != 0 || len(sigs) != 0 {
		t.Fatal("у нового черновика не может быть проверок и подписей")
	}
}

func TestCreateScriptFromCatalogRenders(t *testing.T) {
	s := openTest(t)
	scriptID, versionID, err := s.CreateScript(context.Background(), CreateScriptInput{
		Name: "Перезапуск печати", Kind: gate.KindCatalog, Category: gate.CategoryGeneral,
		CatalogKey: "restart-spooler", Params: map[string]string{"service": "Spooler"},
	}, scriptActor)
	if err != nil {
		t.Fatalf("скрипт из каталога: %v", err)
	}
	v, err := s.VersionContent(context.Background(), scriptID, versionID)
	if err != nil {
		t.Fatalf("версия: %v", err)
	}
	if v.Content == "" || containsRaw(v.Content, "{{param:") {
		t.Fatal("содержимое каталога не отрендерено")
	}
	// Плохие параметры — отказ до базы.
	if _, _, err := s.CreateScript(context.Background(), CreateScriptInput{
		Name: "x", Kind: gate.KindCatalog, CatalogKey: "restart-spooler",
		Params: map[string]string{"service": "a'; evil"}, // недопустимые символы
	}, scriptActor); !errors.Is(err, ErrScriptValue) {
		t.Fatalf("плохие параметры: %v", err)
	}
	// Неизвестный шаблон — отказ.
	if _, _, err := s.CreateScript(context.Background(), CreateScriptInput{
		Name: "x", Kind: gate.KindCatalog, CatalogKey: "нет-такого",
	}, scriptActor); !errors.Is(err, ErrScriptValue) {
		t.Fatalf("неизвестный шаблон: %v", err)
	}
}

func containsRaw(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (haystack == needle || len(needle) == 0 ||
		indexOf(haystack, needle) >= 0)
}

func indexOf(h, n string) int {
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return i
		}
	}
	return -1
}

func TestAdvanceStatusOnlyThroughChain(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	scriptID, versionID, _ := createTestScript(t, s, "Скрипт переходов")

	// Пропуск шага draft → tested запрещён.
	if _, err := s.AdvanceStatus(ctx, scriptID, versionID, gate.StatusTested, "хочу сразу тест", scriptActor); !errors.Is(err, ErrScriptState) {
		t.Fatalf("пропуск шага: %v", err)
	}
	// Ручная отметка без комментария запрещена.
	if _, err := s.AdvanceStatus(ctx, scriptID, versionID, gate.StatusChecked, "", scriptActor); !errors.Is(err, ErrScriptValue) {
		t.Fatalf("отметка без комментария: %v", err)
	}
	// signed ручным маршрутом не ставится никогда.
	if _, err := s.AdvanceStatus(ctx, scriptID, versionID, gate.StatusSigned, "просто подписать", scriptActor); !errors.Is(err, ErrScriptState) {
		t.Fatalf("ручной signed: %v", err)
	}
	// Вперёд по цепочке вручную — с комментарием и записью в аудит.
	if _, err := s.AdvanceStatus(ctx, scriptID, versionID, gate.StatusChecked, "анализатор не доступен, проверено на стенде вручную", scriptActor); err != nil {
		t.Fatalf("ручной checked: %v", err)
	}
	if _, err := s.AdvanceStatus(ctx, scriptID, versionID, gate.StatusTested, "тест на ВМ по записи журнала стенда", scriptActor); err != nil {
		t.Fatalf("ручной tested: %v", err)
	}
	_, versions, checks, _, err := s.ScriptCard(ctx, scriptID)
	if err != nil {
		t.Fatalf("карточка: %v", err)
	}
	if versions[0].Status != gate.StatusTested {
		t.Fatalf("статус после ручных отметок: %q", versions[0].Status)
	}
	if len(checks[versionID]) != 2 {
		t.Fatalf("ручные отметки должны попасть в test_runs: %d", len(checks[versionID]))
	}
	for _, c := range checks[versionID] {
		if c.Source != "manual" || c.Comment == "" {
			t.Fatalf("ручная отметка без source=manual или без комментария: %+v", c)
		}
	}
}

func TestRecordCheckAdvancesStatus(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	scriptID, versionID, _ := createTestScript(t, s, "Скрипт проверок")

	// Провал статпроверки — статус не меняется.
	if _, err := s.RecordCheck(ctx, scriptID, versionID, CheckRow{Kind: "static", Source: "server", Actor: "server", Detail: "2 ошибки"}, false); err != nil {
		t.Fatalf("запись провала: %v", err)
	}
	_, versions, _, _, _ := s.ScriptCard(ctx, scriptID)
	if versions[0].Status != gate.StatusDraft {
		t.Fatalf("после провала статус %q", versions[0].Status)
	}
	// Проходная статпроверка — checked.
	if _, err := s.RecordCheck(ctx, scriptID, versionID, CheckRow{Kind: "static", Source: "server", Actor: "server"}, true); err != nil {
		t.Fatalf("static pass: %v", err)
	}
	// Проходной тест ВМ со стенда — tested.
	if _, err := s.RecordCheck(ctx, scriptID, versionID, CheckRow{Kind: "vm", Source: "stand", Actor: "stand"}, true); err != nil {
		t.Fatalf("vm pass: %v", err)
	}
	_, versions, _, _, _ = s.ScriptCard(ctx, scriptID)
	if versions[0].Status != gate.StatusTested {
		t.Fatalf("после vm pass статус %q", versions[0].Status)
	}
	// Повторная статпроверка поверх tested: CanAdvance(tested→checked) запрещён.
	if _, err := s.RecordCheck(ctx, scriptID, versionID, CheckRow{Kind: "static", Source: "stand", Actor: "stand"}, true); !errors.Is(err, ErrScriptState) {
		t.Fatalf("повторный checked поверх tested: %v", err)
	}
	// Ручной источник без комментария — отказ.
	if _, err := s.RecordCheck(ctx, scriptID, versionID, CheckRow{Kind: "static", Source: "manual", Actor: scriptActor}, true); !errors.Is(err, ErrScriptValue) {
		t.Fatalf("manual без комментария: %v", err)
	}
}

func TestSignVersionFlow(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	scriptID, versionID, sha := createTestScript(t, s, "Скрипт подписи")

	// Подпись до теста — отказ.
	expires := time.Now().Add(24 * time.Hour)
	sig, _ := signing.SignScript(mustHex(sha), expires, priv)
	if _, err := s.SignVersion(ctx, scriptID, versionID, sha, hex.EncodeToString(sig), expires, scriptActor); !errors.Is(err, ErrScriptState) {
		t.Fatalf("подпись до tested: %v", err)
	}
	pushThroughPipeline(t, s, scriptID, versionID)

	// Подпись с чужим хэшем — отказ (подписывается то, что видит владелец).
	if _, err := s.SignVersion(ctx, scriptID, versionID, "00ff", hex.EncodeToString(sig), expires, scriptActor); !errors.Is(err, ErrScriptState) {
		t.Fatalf("подпись чужого хэша: %v", err)
	}
	// Корректная подпись: статус → signed, запись подписи.
	if _, err := s.SignVersion(ctx, scriptID, versionID, sha, hex.EncodeToString(sig), expires, scriptActor); err != nil {
		t.Fatalf("подпись: %v", err)
	}
	_, versions, _, sigs, _ := s.ScriptCard(ctx, scriptID)
	if versions[0].Status != gate.StatusSigned {
		t.Fatalf("статус после подписи: %q", versions[0].Status)
	}
	sr, ok := sigs[versionID]
	if !ok || sr.SignedBy != scriptActor || sr.SHA256 != sha {
		t.Fatalf("подпись не записана: %+v", sr)
	}
	// Проверка криптографии в обе стороны.
	if err := signing.VerifyScript(mustHex(sha), expires, sig, pub); err != nil {
		t.Fatalf("верификация: %v", err)
	}
	if err := signing.VerifyScript(mustHex(sha), expires.Add(time.Hour), sig, pub); err == nil {
		t.Fatal("подпись другого срока прошла проверку")
	}
}

func mustHex(sha string) []byte {
	b, _ := hex.DecodeString(sha)
	return b
}

func TestNewVersionResetsToDraft(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	scriptID, versionID, _ := createTestScript(t, s, "Скрипт с новой версией")
	pushThroughPipeline(t, s, scriptID, versionID)
	if _, err := s.AdvanceStatus(ctx, scriptID, versionID, gate.StatusRejected, "подход не сработал", scriptActor); err != nil {
		t.Fatalf("rejected: %v", err)
	}
	// Новая версия — всегда draft, конвейер начинается заново.
	versionID2, err := s.CreateVersion(ctx, scriptID, CreateScriptInput{
		Name: "Скрипт с новой версией", Kind: gate.KindScript, Category: gate.CategoryGeneral,
		Content: "# v2\nWrite-Output hi2\n",
	}, scriptActor)
	if err != nil {
		t.Fatalf("новая версия: %v", err)
	}
	if versionID2 == versionID {
		t.Fatal("новая версия получила id старой")
	}
	_, versions, _, _, _ := s.ScriptCard(ctx, scriptID)
	if versions[0].Status != gate.StatusDraft || versions[0].ID != versionID2 {
		t.Fatalf("новая версия не draft: %+v", versions[0])
	}
	if len(versions) != 2 {
		t.Fatalf("версий %d, хочу 2", len(versions))
	}
	// Смена типа скрипта в новой версии запрещена.
	if _, err := s.CreateVersion(ctx, scriptID, CreateScriptInput{
		Name: "Скрипт с новой версией", Kind: gate.KindCatalog, CatalogKey: "clear-spooler",
	}, scriptActor); !errors.Is(err, ErrScriptValue) {
		t.Fatalf("смена типа: %v", err)
	}
}

func TestStageCounts(t *testing.T) {
	s := openTest(t)
	createTestScript(t, s, "Один")
	createTestScript(t, s, "Два")
	counts, err := s.StageCounts(context.Background())
	if err != nil {
		t.Fatalf("счётчики: %v", err)
	}
	if counts[gate.StatusDraft] != 2 {
		t.Fatalf("draft %d, хочу 2", counts[gate.StatusDraft])
	}
}

func TestScriptValidation(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	long := make([]byte, MaxScriptNameLen+1)
	for i := range long {
		long[i] = 'x'
	}
	if _, _, err := s.CreateScript(ctx, CreateScriptInput{Name: string(long), Kind: gate.KindScript, Content: "x"}, scriptActor); !errors.Is(err, ErrScriptValue) {
		t.Fatalf("длинное имя: %v", err)
	}
	if _, _, err := s.CreateScript(ctx, CreateScriptInput{Name: "x", Kind: "nope", Content: "x"}, scriptActor); !errors.Is(err, ErrScriptValue) {
		t.Fatalf("тип: %v", err)
	}
	if _, _, err := s.CreateScript(ctx, CreateScriptInput{Name: "x", Kind: gate.KindScript, Category: "nope", Content: "x"}, scriptActor); !errors.Is(err, ErrScriptValue) {
		t.Fatalf("категория: %v", err)
	}
	if _, _, err := s.CreateScript(ctx, CreateScriptInput{Name: "x", Kind: gate.KindScript}, scriptActor); !errors.Is(err, ErrScriptValue) {
		t.Fatalf("пустое содержимое: %v", err)
	}
}

// VersionBySHA256: связывание результата со стенда по хэшу.
func TestVersionBySHA256(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	_, versionID, sha := createTestScript(t, s, "По хэшу")
	sid, vid, err := s.VersionBySHA256(ctx, sha)
	if err != nil {
		t.Fatalf("по хэшу: %v", err)
	}
	if vid != versionID {
		t.Fatalf("версия %d, хочу %d", vid, versionID)
	}
	if sid == 0 {
		t.Fatal("id скрипта пустой")
	}
	// Неизвестный хэш — ErrNotFound.
	if _, _, err := s.VersionBySHA256(ctx, strings.Repeat("ab", 32)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("неизвестный хэш: %v", err)
	}
	// Битый хэш — ErrScriptValue.
	if _, _, err := s.VersionBySHA256(ctx, "zz"); !errors.Is(err, ErrScriptValue) {
		t.Fatalf("битый хэш: %v", err)
	}
}

// Журнал теста со стенда хранится вместе с проверкой (NR-026).
func TestRecordCheckWithLog(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	scriptID, versionID, _ := createTestScript(t, s, "С журналом")
	// Сначала статпроверка (draft → checked), затем тест ВМ со стенда.
	if _, err := s.RecordCheck(ctx, scriptID, versionID, CheckRow{
		Kind: "static", Source: "stand", Actor: "stand", Log: "PSScriptAnalyzer: 0 ошибок",
	}, true); err != nil {
		t.Fatalf("статпроверка: %v", err)
	}
	if _, err := s.RecordCheck(ctx, scriptID, versionID, CheckRow{
		Kind: "vm", Source: "stand", Actor: "stand",
		Detail: `{"metrics":{"free_space_gb":42.5}}`,
		Log:    "Hyper-V: снимок восстановлен, скрипт выполнен за 12 с",
	}, true); err != nil {
		t.Fatalf("запись с журналом: %v", err)
	}
	_, versions, checks, _, _ := s.ScriptCard(ctx, scriptID)
	if versions[0].Status != gate.StatusTested {
		t.Fatalf("статус после vm pass: %q", versions[0].Status)
	}
	if got := checks[versionID][0].Log; got == "" {
		t.Fatal("журнал теста не прочитался")
	}
	// Журнал больше 256 КБ — отказ.
	if _, err := s.RecordCheck(ctx, scriptID, versionID, CheckRow{
		Kind: "vm", Source: "stand", Actor: "stand", Log: strings.Repeat("x", MaxTestRunLogBytes+1),
	}, true); !errors.Is(err, ErrScriptValue) {
		t.Fatalf("журнал без лимита: %v", err)
	}
}
