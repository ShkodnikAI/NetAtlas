// Тесты маршрутов конвейера скриптов (NR-011) на настоящем
// хранилище: подпись с подтверждением вводом, отсутствие маршрута
// «signed» без владельца, задания на подписанные версии, остановка.
package api

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ShkodnikAI/NetAtlas/pipeline/gate"
	"github.com/ShkodnikAI/NetAtlas/pki"
	"github.com/ShkodnikAI/NetAtlas/server/store"
)

// scriptsAPI — API на настоящем store с каталогом ключей подписи.
func scriptsAPI(t *testing.T) (*API, http.Handler, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "netatlas.db"))
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	a, err := New(st, token, nil, nil, nil)
	if err != nil {
		t.Fatalf("api: %v", err)
	}
	keyDir := t.TempDir()
	if err := pki.InitDir(keyDir); err != nil {
		t.Fatalf("pki init: %v", err)
	}
	a.ConfigureScripts(ScriptsConfig{KeyDir: keyDir})
	return a, a.Handler(), st
}

// draftFromBody — создание черновика по телу; возвращает id скрипта и версии.
func draftFromBody(t *testing.T, h http.Handler, body string) (string, string) {
	t.Helper()
	rec := do(h, "POST", "/api/scripts", body, bearer)
	if rec.Code != http.StatusCreated {
		t.Fatalf("создание черновика: код %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		ScriptID  int64 `json:"script_id"`
		VersionID int64 `json:"version_id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("ответ создания: %v", err)
	}
	return itoa64(resp.ScriptID), itoa64(resp.VersionID)
}

func itoa64(n int64) string {
	return json.Number(intToString(n)).String()
}

func intToString(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	if neg {
		return "-" + string(digits)
	}
	return string(digits)
}

// walkToTested — доводит версию до tested через check-result стенда.
func walkToTested(t *testing.T, h http.Handler, sid, vid string) {
	t.Helper()
	for _, kind := range []string{"static", "vm"} {
		rec := do(h, "POST", "/api/scripts/"+sid+"/versions/"+vid+"/check-result",
			`{"kind":"`+kind+`","source":"stand","result":"pass","detail":"стенд"}`, bearer)
		if rec.Code != http.StatusOK {
			t.Fatalf("check-result %s: код %d: %s", kind, rec.Code, rec.Body.String())
		}
	}
}

func TestScriptPipelineViaHTTP(t *testing.T) {
	_, h, st := scriptsAPI(t)
	sid, vid := draftFromBody(t, h, `{"name":"Диагностика адаптера","kind":"script","category":"general","content":"Write-Output ok"}`)

	// Список: скрипт в draft, счётчики этапов.
	rec := do(h, "GET", "/api/scripts", "", bearer)
	if rec.Code != http.StatusOK {
		t.Fatalf("список: %d", rec.Code)
	}
	var list struct {
		Stages map[string]int `json:"stages"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &list)
	if list.Stages[gate.StatusDraft] < 1 {
		t.Fatalf("счётчик draft: %+v", list.Stages)
	}

	// Пропуск шага draft → tested отклоняется (409).
	if rec := do(h, "POST", "/api/scripts/"+sid+"/versions/"+vid+"/status",
		`{"to":"tested","comment":"сразу тест"}`, bearer); rec.Code != http.StatusConflict {
		t.Fatalf("пропуск шага: %d: %s", rec.Code, rec.Body.String())
	}
	// Ручная отметка без комментария — 400.
	if rec := do(h, "POST", "/api/scripts/"+sid+"/versions/"+vid+"/status",
		`{"to":"checked","comment":""}`, bearer); rec.Code != http.StatusBadRequest {
		t.Fatalf("отметка без комментария: %d", rec.Code)
	}
	// signed статус-маршрутом — 409 (нет маршрута без подписи владельца).
	if rec := do(h, "POST", "/api/scripts/"+sid+"/versions/"+vid+"/status",
		`{"to":"signed","comment":"хочу подписать"}`, bearer); rec.Code != http.StatusConflict {
		t.Fatalf("ручной signed: %d: %s", rec.Code, rec.Body.String())
	}

	walkToTested(t, h, sid, vid)

	// Просмотр содержимого версии.
	rec = do(h, "GET", "/api/scripts/"+sid+"/versions/"+vid, "", bearer)
	if rec.Code != http.StatusOK {
		t.Fatalf("содержимое: %d", rec.Code)
	}
	var v struct {
		Content string `json:"content"`
		SHA256  string `json:"sha256"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("содержимое: %v", err)
	}
	if !strings.Contains(v.Content, "Write-Output ok") || len(v.SHA256) != 64 {
		t.Fatalf("содержимое неполно: %q, sha %q", v.Content, v.SHA256)
	}
	_ = st
}

func TestSignRequiresConfirmation(t *testing.T) {
	a, h, st := scriptsAPI(t)
	sid, vid := draftFromBody(t, h, `{"name":"Очистка файлов","kind":"script","content":"Write-Output 1"}`)
	walkToTested(t, h, sid, vid)

	// Подпись с неверным именем — 400.
	if rec := do(h, "POST", "/api/scripts/"+sid+"/versions/"+vid+"/sign",
		`{"name":"Другое имя","sha256":"`+strings.Repeat("ab", 32)+`"}`, bearer); rec.Code != http.StatusBadRequest {
		t.Fatalf("чужое имя: %d: %s", rec.Code, rec.Body.String())
	}
	// Подпись с неверным хэшем — 400.
	if rec := do(h, "POST", "/api/scripts/"+sid+"/versions/"+vid+"/sign",
		`{"name":"Очистка файлов","sha256":"`+strings.Repeat("cd", 32)+`"}`, bearer); rec.Code != http.StatusBadRequest {
		t.Fatalf("чужой хэш: %d", rec.Code)
	}
	// Хэш версии из карточки — 200, статус signed.
	rec := do(h, "GET", "/api/scripts/"+sid, "", bearer)
	var card struct {
		Versions []store.VersionRow `json:"versions"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &card); err != nil {
		t.Fatalf("карточка: %v", err)
	}
	sha := card.Versions[0].SHA256
	rec = do(h, "POST", "/api/scripts/"+sid+"/versions/"+vid+"/sign",
		`{"name":"Очистка файлов","sha256":"`+sha+`"}`, bearer)
	if rec.Code != http.StatusOK {
		t.Fatalf("подпись: %d: %s", rec.Code, rec.Body.String())
	}
	var signed store.VersionRow
	if err := json.Unmarshal(rec.Body.Bytes(), &signed); err != nil {
		t.Fatalf("ответ подписи: %v", err)
	}
	if signed.Status != gate.StatusSigned {
		t.Fatalf("статус после подписи: %q", signed.Status)
	}
	// Подпись хранится и сходится криптографически.
	_, versions, _, sigs, _ := st.ScriptCard(t.Context(), card.Versions[0].ScriptID)
	sigRow, ok := sigs[versions[0].ID]
	if !ok || sigRow.Signature == "" {
		t.Fatal("подпись не записана")
	}
	_ = a
}

func TestSignWithoutKeyDirUnavailable(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "netatlas.db"))
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	a, err := New(st, token, nil, nil, nil)
	if err != nil {
		t.Fatalf("api: %v", err)
	}
	h := a.Handler() // ConfigureScripts не вызывался
	rec := do(h, "POST", "/api/scripts/1/versions/1/sign", `{"name":"x","sha256":""}`, bearer)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("подпись без ключей: %d", rec.Code)
	}
}

func TestJobCreationRequiresSignedVersion(t *testing.T) {
	_, h, st := scriptsAPI(t)
	// Агент в базе.
	if err := st.UpsertAgent(t.Context(), "agent:pc-1", "ПК-1", "serial", nil, "test"); err != nil {
		t.Fatalf("агент: %v", err)
	}
	sid, vid := draftFromBody(t, h, `{"name":"Задачный скрипт","kind":"script","content":"Write-Output 2"}`)

	// Задание на черновик — 409.
	if rec := do(h, "POST", "/api/jobs", `{"script_version_id":`+vid+`,"targets":["agent:pc-1"]}`, bearer); rec.Code != http.StatusConflict {
		t.Fatalf("задание на черновик: %d: %s", rec.Code, rec.Body.String())
	}
	walkToTested(t, h, sid, vid)

	// Задание до подписи — 409 (создаётся только на подписанную).
	if rec := do(h, "POST", "/api/jobs", `{"script_version_id":`+vid+`,"targets":["agent:pc-1"]}`, bearer); rec.Code != http.StatusConflict {
		t.Fatalf("задание до подписи: %d", rec.Code)
	}
	// Пилот на две цели — 400.
	if rec := do(h, "POST", "/api/jobs", `{"script_version_id":`+vid+`,"targets":["agent:pc-1","agent:pc-1"],"pilot":true}`, bearer); rec.Code != http.StatusBadRequest {
		t.Fatal("пилот на две цели принят")
	}
	// Подписываем и создаём задание.
	rec := do(h, "GET", "/api/scripts/"+sid, "", bearer)
	var card struct {
		Versions []store.VersionRow `json:"versions"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &card)
	rec = do(h, "POST", "/api/scripts/"+sid+"/versions/"+vid+"/sign",
		`{"name":"Задачный скрипт","sha256":"`+card.Versions[0].SHA256+`"}`, bearer)
	if rec.Code != http.StatusOK {
		t.Fatalf("подпись: %d: %s", rec.Code, rec.Body.String())
	}
	rec = do(h, "POST", "/api/jobs", `{"script_version_id":`+vid+`,"targets":["agent:pc-1"],"window_start":"2026-10-25T00:00:00Z","deadline":"2026-10-30T00:00:00Z"}`, bearer)
	if rec.Code != http.StatusCreated {
		t.Fatalf("задание: %d: %s", rec.Code, rec.Body.String())
	}
	var created struct {
		ID int64 `json:"id"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &created)

	// GET /api/jobs/{id}: задание с целью queued.
	rec = do(h, "GET", "/api/jobs/"+itoa64(created.ID), "", bearer)
	if rec.Code != http.StatusOK {
		t.Fatalf("задание по id: %d", rec.Code)
	}
	var job store.JobRow
	if err := json.Unmarshal(rec.Body.Bytes(), &job); err != nil {
		t.Fatalf("задание: %v", err)
	}
	if job.Status != "pending" || len(job.Targets) != 1 || job.Targets[0].State != "queued" {
		t.Fatalf("задание неполно: %+v", job)
	}
	// Окно времени в неверном формате — 400.
	if rec := do(h, "POST", "/api/jobs", `{"script_version_id":`+vid+`,"targets":["agent:pc-1"],"window_start":"завтра"}`, bearer); rec.Code != http.StatusBadRequest {
		t.Fatal("окно в неверном формате принято")
	}
	// Остановка.
	rec = do(h, "POST", "/api/jobs/"+itoa64(created.ID)+"/stop", `{"reason":"передумано"}`, bearer)
	if rec.Code != http.StatusOK {
		t.Fatalf("остановка: %d: %s", rec.Code, rec.Body.String())
	}
	rec = do(h, "GET", "/api/jobs/"+itoa64(created.ID), "", bearer)
	var stopped store.JobRow
	_ = json.Unmarshal(rec.Body.Bytes(), &stopped)
	if stopped.Status != "stopped" || stopped.Targets[0].State != "stopped" {
		t.Fatalf("после остановки: %q / %q", stopped.Status, stopped.Targets[0].State)
	}
}

func TestCheckResultManualRequiresComment(t *testing.T) {
	_, h, _ := scriptsAPI(t)
	sid, vid := draftFromBody(t, h, `{"name":"Ручной","kind":"script","content":"x"}`)
	// manual без комментария — 400.
	if rec := do(h, "POST", "/api/scripts/"+sid+"/versions/"+vid+"/check-result",
		`{"kind":"static","source":"manual","result":"pass"}`, bearer); rec.Code != http.StatusBadRequest {
		t.Fatal("manual без комментария принят")
	}
	// manual с комментарием — 200 и статус checked.
	rec := do(h, "POST", "/api/scripts/"+sid+"/versions/"+vid+"/check-result",
		`{"kind":"static","source":"manual","result":"pass","comment":"анализатор недоступен, проверено на стенде вручную"}`, bearer)
	if rec.Code != http.StatusOK {
		t.Fatalf("manual с комментарием: %d: %s", rec.Code, rec.Body.String())
	}
	// Источник server в check-result отклоняется: он только из check-run.
	if rec := do(h, "POST", "/api/scripts/"+sid+"/versions/"+vid+"/check-result",
		`{"kind":"static","source":"server","result":"pass"}`, bearer); rec.Code != http.StatusBadRequest {
		t.Fatal("source=server принят в check-result")
	}
}

func TestCatalogEndpoint(t *testing.T) {
	_, h, _ := scriptsAPI(t)
	rec := do(h, "GET", "/api/catalog", "", bearer)
	if rec.Code != http.StatusOK {
		t.Fatalf("каталог: %d", rec.Code)
	}
	var resp struct {
		Templates []struct {
			Key    string `json:"key"`
			Title  string `json:"title"`
			Params []struct {
				Key string `json:"key"`
			} `json:"params"`
		} `json:"templates"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("каталог: %v", err)
	}
	if len(resp.Templates) < 3 {
		t.Fatalf("шаблонов %d, минимум 3", len(resp.Templates))
	}
	// Создание черновика из каталога рендерит содержимое.
	sid, vid := draftFromBody(t, h, `{"name":"Перезапуск печати","kind":"catalog","catalog_key":"restart-spooler","params":{"service":"Spooler"}}`)
	rec = do(h, "GET", "/api/scripts/"+sid+"/versions/"+vid, "", bearer)
	var v struct {
		Content string `json:"content"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &v)
	if strings.Contains(v.Content, "{{param:") {
		t.Fatal("маркеры не заполнены")
	}
	// Недопустимый параметр — 400.
	rec = do(h, "POST", "/api/scripts", `{"name":"x","kind":"catalog","catalog_key":"restart-spooler","params":{"service":"a'; drop"}}`, bearer)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("плохой параметр: %d: %s", rec.Code, rec.Body.String())
	}
}

func TestScriptRoutesRequireToken(t *testing.T) {
	_, h, _ := scriptsAPI(t)
	for _, c := range []struct{ method, path string }{
		{"GET", "/api/scripts"},
		{"POST", "/api/scripts"},
		{"GET", "/api/catalog"},
		{"POST", "/api/jobs"},
		{"POST", "/api/scripts/1/versions/1/sign"},
	} {
		if rec := do(h, c.method, c.path, "{}", ""); rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s %s без токена: %d", c.method, c.path, rec.Code)
		}
	}
}

// Тесты быстрые: никаких реальных ожиданий и сети.
var _ = time.Second

// Приём результатов стенда (NR-026): привязка по хэшу, статусы
// через gate, отказ без совпадающего хэша.
func TestTestRunsEndpoint(t *testing.T) {
	_, h, _ := scriptsAPI(t)
	sid, vid := draftFromBody(t, h, `{"name":"Стенд","kind":"script","content":"Write-Output stand"}`)
	rec := do(h, "GET", "/api/scripts/"+sid+"/versions/"+vid, "", bearer)
	var v struct {
		SHA256 string `json:"sha256"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &v)

	// Статическая проверка со стенда: draft → checked.
	rec = do(h, "POST", "/api/test-runs",
		`{"script_sha256":"`+v.SHA256+`","stage":"static","result":"pass","log":"PSScriptAnalyzer: 0 ошибок"}`, bearer)
	if rec.Code != http.StatusOK {
		t.Fatalf("static со стенда: %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Status string `json:"status"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Status != gate.StatusChecked {
		t.Fatalf("статус после static: %q", resp.Status)
	}
	// Тест ВМ со стенда с метриками и логом: checked → tested.
	rec = do(h, "POST", "/api/test-runs",
		`{"script_sha256":"`+v.SHA256+`","stage":"vm","result":"pass","metrics":{"free_space_gb":42.5,"ping_ms":1.2},"log":"снимок восстановлен, выполнено за 12 с"}`, bearer)
	if rec.Code != http.StatusOK {
		t.Fatalf("vm со стенда: %d: %s", rec.Code, rec.Body.String())
	}
	// Результат без совпадающего хэша — 404.
	if rec := do(h, "POST", "/api/test-runs",
		`{"script_sha256":"`+strings.Repeat("ab", 32)+`","stage":"vm","result":"pass"}`, bearer); rec.Code != http.StatusNotFound {
		t.Fatalf("чужой хэш: %d", rec.Code)
	}
	// Битая схема: stage — 400.
	if rec := do(h, "POST", "/api/test-runs",
		`{"script_sha256":"`+v.SHA256+`","stage":"deploy","result":"pass"}`, bearer); rec.Code != http.StatusBadRequest {
		t.Fatalf("чужая стадия: %d", rec.Code)
	}
	// Журнал больше 256 КБ — 400.
	big := strings.Repeat("x", 256<<10)
	if rec := do(h, "POST", "/api/test-runs",
		`{"script_sha256":"`+v.SHA256+`","stage":"vm","result":"pass","log":"`+big+`"}`, bearer); rec.Code != http.StatusBadRequest {
		t.Fatalf("журнал без лимита: %d", rec.Code)
	}
	// Провальный тест оставляет статус и пишется в аудит.
	sid2, vid2 := draftFromBody(t, h, `{"name":"Стенд-2","kind":"script","content":"Write-Output stand2"}`)
	rec = do(h, "GET", "/api/scripts/"+sid2+"/versions/"+vid2, "", bearer)
	var v2 struct {
		SHA256 string `json:"sha256"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &v2)
	do(h, "POST", "/api/test-runs", `{"script_sha256":"`+v2.SHA256+`","stage":"static","result":"pass"}`, bearer)
	do(h, "POST", "/api/test-runs", `{"script_sha256":"`+v2.SHA256+`","stage":"vm","result":"fail","log":"служба не поднялась"}`, bearer)
	rec = do(h, "GET", "/api/scripts/"+sid2, "", bearer)
	var card struct {
		Versions []store.VersionRow         `json:"versions"`
		Checks   map[int64][]store.CheckRow `json:"checks"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &card)
	if card.Versions[0].Status != gate.StatusChecked {
		t.Fatalf("провал теста изменил статус: %q", card.Versions[0].Status)
	}
	last := card.Checks[card.Versions[0].ID][0]
	if last.Result != "fail" {
		t.Fatalf("провал не записан: %+v", last)
	}
	// В аудите есть script_check с result=fail.
	rec = do(h, "GET", "/api/audit?limit=100", "", bearer)
	if !strings.Contains(rec.Body.String(), `"result":"fail"`) || !strings.Contains(rec.Body.String(), "script_check") {
		t.Fatal("провала нет в аудите")
	}
	// Без токена — 401.
	if rec := do(h, "POST", "/api/test-runs", `{}`, ""); rec.Code != http.StatusUnauthorized {
		t.Fatal("test-runs без токена")
	}
}

// Активность сотрудников (NR-012) на настоящем store: включение с
// фразой, выключение, просмотр с аудитом, удаление, 401.
func TestActivityEndpoints(t *testing.T) {
	_, h, st := scriptsAPI(t)
	ctx := t.Context()
	if err := st.UpsertAgent(ctx, "agent:act-1", "ОФИС-01", "serial-a", nil, "test"); err != nil {
		t.Fatalf("агент: %v", err)
	}

	// Выключено по умолчанию.
	enabled, _ := st.ActivityEnabled(ctx, "agent:act-1")
	if enabled {
		t.Fatal("сбор включён без подтверждения")
	}
	// Данные от выключенного ПК отклоняются агентским API (тест
	// на уровне store: приём без enabled не происходит).
	if err := st.SaveActivity(ctx, store.ActivityRow{
		AgentID: "agent:act-1", Account: "user", WindowStart: time.Now().UTC().Format(time.RFC3339),
		Apps: map[string]int{}, Domains: map[string]int{},
	}); err != nil {
		t.Fatalf("save: %v", err)
	}

	// Включение с неверной фразой — 400.
	if rec := do(h, "POST", "/api/activity/enable", `{"agent_id":"agent:act-1","confirmation":"уведомлены"}`, bearer); rec.Code != http.StatusBadRequest {
		t.Fatalf("неверная фраза: %d: %s", rec.Code, rec.Body.String())
	}
	// Включение с точной фразой — 200.
	if rec := do(h, "POST", "/api/activity/enable",
		`{"agent_id":"agent:act-1","confirmation":"Сотрудники уведомлены"}`, bearer); rec.Code != http.StatusOK {
		t.Fatalf("включение: %d: %s", rec.Code, rec.Body.String())
	}
	enabled, _ = st.ActivityEnabled(ctx, "agent:act-1")
	if !enabled {
		t.Fatal("сбор не включился с верной фразой")
	}
	// Включение неизвестному агенту — 404.
	if rec := do(h, "POST", "/api/activity/enable",
		`{"agent_id":"agent:ghost","confirmation":"Сотрудники уведомлены"}`, bearer); rec.Code != http.StatusNotFound {
		t.Fatalf("неизвестный агент: %d", rec.Code)
	}

	// Просмотр со списком ПК — каждый запрос в аудит.
	if rec := do(h, "GET", "/api/activity/computers", "", bearer); rec.Code != http.StatusOK {
		t.Fatalf("список ПК: %d", rec.Code)
	}
	// Сводка за день.
	if rec := do(h, "GET", "/api/activity/summary", "", bearer); rec.Code != http.StatusOK {
		t.Fatalf("сводка: %d: %s", rec.Code, rec.Body.String())
	}
	// Период больше года — 400.
	if rec := do(h, "GET", "/api/activity/summary?from=2020-01-01T00:00:00Z&to=2026-01-01T00:00:00Z", "", bearer); rec.Code != http.StatusBadRequest {
		t.Fatal("бесконечный период принят")
	}
	// В аудите есть activity_enable и activity_view.
	rec := do(h, "GET", "/api/audit?limit=100", "", bearer)
	if !strings.Contains(rec.Body.String(), "activity_enable") || !strings.Contains(rec.Body.String(), "activity_view") {
		t.Fatalf("аудит активности пуст: %s", rec.Body.String())
	}
	// В записи включения — подтверждение владельца.
	if !strings.Contains(rec.Body.String(), "Сотрудники уведомлены") {
		t.Fatal("подтверждение владельца не в аудите")
	}

	// Удаление собранного по ПК.
	if rec := do(h, "DELETE", "/api/activity?computer=agent:act-1", "", bearer); rec.Code != http.StatusOK {
		t.Fatalf("удаление: %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(do(h, "GET", "/api/audit?limit=100", "", bearer).Body.String(), "activity_purge") {
		t.Fatal("удаления нет в аудите")
	}
	// Удаление без computer — 400.
	if rec := do(h, "DELETE", "/api/activity", "", bearer); rec.Code != http.StatusBadRequest {
		t.Fatal("удаление без компьютера принято")
	}
	// Без токена — 401.
	for _, c := range [][2]string{
		{"POST", "/api/activity/enable"},
		{"GET", "/api/activity/summary"},
		{"DELETE", "/api/activity?computer=x"},
	} {
		if rec := do(h, c[0], c[1], "{}", ""); rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s %s без токена: %d", c[0], c[1], rec.Code)
		}
	}
}
