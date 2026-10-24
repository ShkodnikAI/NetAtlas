// Тесты диспетчеризации заданий (NR-011): шлюз gate в checkin.
// Негативные сценарии из наряда: неподписанный, статус ниже tested,
// изменённый после подписи, просроченная подпись, цель вне набора,
// драйвер без пилота, kind=script без права, выключенная
// диспетчеризация. Плюс: раскатка группами и job-result.
package agentapi

import (
	"encoding/json"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/ShkodnikAI/NetAtlas/pipeline/gate"
	"github.com/ShkodnikAI/NetAtlas/pki"
	"github.com/ShkodnikAI/NetAtlas/server/store"
)

// dispatchEnv — среда с диспетчеризацией (ключ подписи из каталога).
type dispatchEnv struct {
	e     *env
	jobID int64
}

func newDispatchEnv(t *testing.T, allowCustom bool) *dispatchEnv {
	t.Helper()
	e := newEnv(t, DefaultRevocationTTL)
	keyDir := t.TempDir()
	if err := pki.InitDir(keyDir); err != nil {
		t.Fatalf("InitDir: %v", err)
	}
	key, err := pki.LoadSigningKey(keyDir)
	if err != nil {
		t.Fatalf("ключ подписи: %v", err)
	}
	e.api.ConfigureDispatch(&DispatchDeps{AllowCustomScripts: allowCustom, Key: key})
	return &dispatchEnv{e: e}
}

// agent — регистрирует агента, возвращает TLS-клиент.
func (d *dispatchEnv) agent(t *testing.T, cn string) *http.Client {
	t.Helper()
	certPEM, _, priv := d.e.enrollAgent(cn, "ПК-"+cn, nil)
	return certClient(pemDER(t, certPEM), priv)
}

// signedScript — скрипт (kind, category) доведён до статуса signed.
// Возвращает (scriptID, versionID, sha256). Задание не создаётся.
func (d *dispatchEnv) signedScript(t *testing.T, kind, category string, expires time.Time) (int64, int64, string) {
	t.Helper()
	st := d.e.st
	ctx := d.e.t.Context()
	in := store.CreateScriptInput{
		Name: "Задание конвейера", Kind: kind, Category: category,
		Content: "Write-Output dispatch",
	}
	if kind == gate.KindCatalog {
		in.CatalogKey, in.Content = "clear-spooler", ""
	}
	scriptID, versionID, err := st.CreateScript(ctx, in, "owner")
	if err != nil {
		t.Fatalf("скрипт: %v", err)
	}
	for _, k := range []string{"static", "vm"} {
		if _, err := st.RecordCheck(ctx, scriptID, versionID,
			store.CheckRow{Kind: k, Source: "stand", Actor: "stand"}, true); err != nil {
			t.Fatalf("check %s: %v", k, err)
		}
	}
	v, err := st.VersionContent(ctx, scriptID, versionID)
	if err != nil {
		t.Fatalf("версия: %v", err)
	}
	if _, err := st.SignVersion(ctx, scriptID, versionID, v.SHA256, "sig", expires, "owner"); err != nil {
		t.Fatalf("подпись: %v", err)
	}
	return scriptID, versionID, v.SHA256
}

// makeJob — задание на цели; сохраняет id в d.jobID.
func (d *dispatchEnv) makeJob(t *testing.T, versionID int64, targets []string) int64 {
	t.Helper()
	jobID, err := d.e.st.CreateJob(d.e.t.Context(), store.CreateJobInput{
		ScriptVersionID: versionID, Targets: targets,
	}, "owner")
	if err != nil {
		t.Fatalf("задание: %v", err)
	}
	d.jobID = jobID
	return jobID
}

// checkinJobs — jobs из ответа checkin.
func (d *dispatchEnv) checkinJobs(t *testing.T, cl *http.Client) []jobPayload {
	t.Helper()
	code, body := d.e.post(cl, d.e.mtlsURL("/agent/v1/checkin"), nil)
	if code != http.StatusOK {
		t.Fatalf("checkin: код %d: %s", code, body)
	}
	var resp checkinResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("checkin ответ: %v: %s", err, body)
	}
	return resp.Jobs
}

// Диспетчеризация выключена по умолчанию: без ConfigureDispatch
// checkin не отдаёт заданий (негатив 8 из наряда).
func TestDispatchDisabledByDefault(t *testing.T) {
	e := newEnv(t, DefaultRevocationTTL) // ConfigureDispatch не вызывался
	certPEM, _, priv := e.enrollAgent("agent:off", "ПК", nil)
	cl := certClient(pemDER(t, certPEM), priv)
	code, body := e.post(cl, e.mtlsURL("/agent/v1/checkin"), nil)
	if code != http.StatusOK {
		t.Fatalf("checkin: код %d: %s", code, body)
	}
	var resp checkinResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("ответ: %v", err)
	}
	if len(resp.Jobs) != 0 {
		t.Fatalf("диспетчеризация выключена, а заданий %d", len(resp.Jobs))
	}
}

// Полный путь: подписанное задание отдаётся, цель sent, конверт
// подписан, повторный checkin ничего не выдаёт.
func TestDispatchDeliversSignedJob(t *testing.T) {
	d := newDispatchEnv(t, false)
	cl := d.agent(t, "agent:dispatch")
	_, versionID, sha := d.signedScript(t, gate.KindCatalog, gate.CategoryGeneral, time.Now().Add(24*time.Hour))
	d.makeJob(t, versionID, []string{"agent:dispatch"})

	jobs := d.checkinJobs(t, cl)
	if len(jobs) != 1 {
		t.Fatalf("заданий %d, хочу 1", len(jobs))
	}
	j := jobs[0]
	if j.Kind != gate.KindCatalog || j.Content == "" || j.Envelope.JobID == "" {
		t.Fatalf("задание неполно: %+v", j)
	}
	if j.Signature == "" || j.ExpiresAt == "" {
		t.Fatalf("конверт/подпись неполны: %+v", j.Envelope)
	}
	if len(j.Envelope.ContentSHA256) != 32 {
		t.Fatalf("хэш конверта не 32 байта: %d", len(j.Envelope.ContentSHA256))
	}
	// Повторный checkin: задание уже выдано (sent) — список пуст.
	if jobs := d.checkinJobs(t, cl); len(jobs) != 0 {
		t.Fatalf("повторная выдача: %d заданий", len(jobs))
	}
	_ = sha
}

// Неподписанное задание не отдаётся (негатив 1): подпись стирается
// из базы после создания задания.
func TestDispatchSkipsUnsigned(t *testing.T) {
	d := newDispatchEnv(t, false)
	cl := d.agent(t, "agent:dispatch")
	st, ctx := d.e.st, d.e.t.Context()
	scriptID, versionID, err := st.CreateScript(ctx, store.CreateScriptInput{
		Name: "Без подписи", Kind: gate.KindScript, Category: gate.CategoryGeneral, Content: "Write-Output 1",
	}, "owner")
	if err != nil {
		t.Fatalf("скрипт: %v", err)
	}
	for _, k := range []string{"static", "vm"} {
		if _, err := st.RecordCheck(ctx, scriptID, versionID, store.CheckRow{Kind: k, Source: "stand", Actor: "stand"}, true); err != nil {
			t.Fatalf("check: %v", err)
		}
	}
	if _, err := st.SignVersion(ctx, scriptID, versionID, shaOf(t, st, scriptID, versionID),
		"sig", time.Now().Add(24*time.Hour), "owner"); err != nil {
		t.Fatalf("подпись: %v", err)
	}
	d.makeJob(t, versionID, []string{"agent:dispatch"})
	if _, err := st.DB().Exec(`DELETE FROM signatures`); err != nil {
		t.Fatalf("стирание подписи: %v", err)
	}
	if jobs := d.checkinJobs(t, cl); len(jobs) != 0 {
		t.Fatalf("неподписанное задание отдалось: %d", len(jobs))
	}
}

// Статус ниже tested при наличии подписи не отдаётся (негатив 2):
// статус версии принудительно откатывается в базе.
func TestDispatchSkipsStatusBelowTested(t *testing.T) {
	d := newDispatchEnv(t, false)
	cl := d.agent(t, "agent:dispatch")
	_, versionID, _ := d.signedScript(t, gate.KindCatalog, gate.CategoryGeneral, time.Now().Add(24*time.Hour))
	d.makeJob(t, versionID, []string{"agent:dispatch"})
	if _, err := d.e.st.DB().Exec(`UPDATE script_versions SET status = 'checked'`); err != nil {
		t.Fatalf("откат статуса: %v", err)
	}
	if jobs := d.checkinJobs(t, cl); len(jobs) != 0 {
		t.Fatalf("задание со статусом checked отдалось: %d", len(jobs))
	}
}

// Изменённый после подписи хэш не отдаётся (негатив 3).
func TestDispatchSkipsContentChanged(t *testing.T) {
	d := newDispatchEnv(t, false)
	cl := d.agent(t, "agent:dispatch")
	_, versionID, _ := d.signedScript(t, gate.KindCatalog, gate.CategoryGeneral, time.Now().Add(24*time.Hour))
	d.makeJob(t, versionID, []string{"agent:dispatch"})
	if _, err := d.e.st.DB().Exec(`UPDATE script_versions SET sha256 = 'ff' || substr(sha256, 3)`); err != nil {
		t.Fatalf("подмена хэша: %v", err)
	}
	if jobs := d.checkinJobs(t, cl); len(jobs) != 0 {
		t.Fatalf("изменённое после подписи отдалось: %d", len(jobs))
	}
}

// Просроченная подпись: задание не отдаётся, цель помечается
// expired навсегда (негатив 4).
func TestDispatchExpiredMarksTarget(t *testing.T) {
	d := newDispatchEnv(t, false)
	cl := d.agent(t, "agent:dispatch")
	_, versionID, _ := d.signedScript(t, gate.KindCatalog, gate.CategoryGeneral, time.Now().Add(24*time.Hour))
	d.makeJob(t, versionID, []string{"agent:dispatch"})
	// Срок подписи отматывается в прошлое — шлюз видит просрочку.
	if _, err := d.e.st.DB().Exec(`UPDATE signatures SET expires_at = ?`,
		time.Now().Add(-time.Minute).Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("отмотка срока: %v", err)
	}
	if jobs := d.checkinJobs(t, cl); len(jobs) != 0 {
		t.Fatalf("просроченная подпись отдалась: %d", len(jobs))
	}
	job, err := d.e.st.JobByID(d.e.t.Context(), d.jobID)
	if err != nil {
		t.Fatalf("задание: %v", err)
	}
	if job.Targets[0].State != "expired" {
		t.Fatalf("цель не помечена expired: %q", job.Targets[0].State)
	}
	// После продления подписи expired не отдаётся: конечное состояние.
	if _, err := d.e.st.DB().Exec(`UPDATE signatures SET expires_at = ?`,
		time.Now().Add(24*time.Hour).Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("продление: %v", err)
	}
	if jobs := d.checkinJobs(t, cl); len(jobs) != 0 {
		t.Fatalf("expired-цель получила задание: %d", len(jobs))
	}
}

// Цель вне разрешённого набора не получает задание (негатив 5).
func TestDispatchForeignTarget(t *testing.T) {
	d := newDispatchEnv(t, false)
	other := d.agent(t, "agent:other") // не цель задания
	d.agent(t, "agent:target")
	_, versionID, _ := d.signedScript(t, gate.KindCatalog, gate.CategoryGeneral, time.Now().Add(24*time.Hour))
	d.makeJob(t, versionID, []string{"agent:target"})
	if jobs := d.checkinJobs(t, other); len(jobs) != 0 {
		t.Fatalf("чужой агент получил задание: %d", len(jobs))
	}
}

// Драйвер и сетевая карта без пройденного пилота не отдаются
// обычным заданием (негатив 6); пилотное задание проходит, его
// успех открывает обычную выдачу.
func TestDispatchDriverNeedsPilot(t *testing.T) {
	for _, cat := range []string{gate.CategoryDriver, gate.CategoryNic} {
		d := newDispatchEnv(t, false)
		cl := d.agent(t, "agent:dispatch")
		_, versionID, _ := d.signedScript(t, gate.KindCatalog, cat, time.Now().Add(24*time.Hour))
		d.makeJob(t, versionID, []string{"agent:dispatch"})
		if jobs := d.checkinJobs(t, cl); len(jobs) != 0 {
			t.Fatalf("категория %q без пилота отдалась: %d", cat, len(jobs))
		}
	}
	// Пилотное задание (этап «один ПК») для nic проходит шлюз.
	d := newDispatchEnv(t, false)
	cl := d.agent(t, "agent:dispatch")
	_, versionID, _ := d.signedScript(t, gate.KindCatalog, gate.CategoryNic, time.Now().Add(24*time.Hour))
	d.makeJob(t, versionID, []string{"agent:dispatch"})
	// Пересоздаём как пилотное: queued-цель прежнего снимем остановкой.
	if err := d.e.st.StopJob(d.e.t.Context(), d.jobID, "замена пилотным", "owner"); err != nil {
		t.Fatalf("остановка: %v", err)
	}
	pilotID, err := d.e.st.CreateJob(d.e.t.Context(), store.CreateJobInput{
		ScriptVersionID: versionID, Targets: []string{"agent:dispatch"}, Pilot: true,
	}, "owner")
	if err != nil {
		t.Fatalf("пилотное задание: %v", err)
	}
	d.jobID = pilotID
	if jobs := d.checkinJobs(t, cl); len(jobs) != 1 {
		t.Fatalf("пилотное задание nic не отдалось: %d", len(jobs))
	}
	if _, err := d.e.st.RecordJobResult(d.e.t.Context(), pilotID, "agent:dispatch", true, "пилот ок", nil, nil, ActorAgentAPI); err != nil {
		t.Fatalf("пилот-результат: %v", err)
	}
	// После пройденного пилота обычное задание на ту же версию отдаётся.
	d.makeJob(t, versionID, []string{"agent:dispatch"})
	if jobs := d.checkinJobs(t, cl); len(jobs) != 1 {
		t.Fatalf("после пилота nic не отдаётся: %d", len(jobs))
	}
}

// kind=script при выключенном allow_custom_scripts не отдаётся
// (негатив 7); с включённым — отдаётся.
func TestDispatchCustomScriptsPolicy(t *testing.T) {
	d := newDispatchEnv(t, false) // произвольные скрипты выключены
	cl := d.agent(t, "agent:dispatch")
	_, versionID, _ := d.signedScript(t, gate.KindScript, gate.CategoryGeneral, time.Now().Add(24*time.Hour))
	d.makeJob(t, versionID, []string{"agent:dispatch"})
	if jobs := d.checkinJobs(t, cl); len(jobs) != 0 {
		t.Fatalf("kind=script без права отдался: %d", len(jobs))
	}
	// Включаем право — задание отдаётся (цель всё ещё queued).
	d.e.api.ConfigureDispatch(&DispatchDeps{AllowCustomScripts: true, Key: d.e.api.dispatch.Key})
	if jobs := d.checkinJobs(t, cl); len(jobs) != 1 {
		t.Fatalf("kind=script с правом не отдался: %d", len(jobs))
	}
}

// Раскатка группами: 3 цели — сначала одна; после её успеха —
// следующая.
func TestDispatchRolloutGroups(t *testing.T) {
	d := newDispatchEnv(t, false)
	ctx := d.e.t.Context()
	st := d.e.st
	for _, cn := range []string{"agent:r1", "agent:r2", "agent:r3"} {
		d.agent(t, cn)
	}
	_, versionID, _ := d.signedScript(t, gate.KindCatalog, gate.CategoryGeneral, time.Now().Add(24*time.Hour))
	jobID, err := st.CreateJob(ctx, store.CreateJobInput{
		ScriptVersionID: versionID, Targets: []string{"agent:r1", "agent:r2", "agent:r3"},
	}, "owner")
	if err != nil {
		t.Fatalf("задание на 3 цели: %v", err)
	}
	d.jobID = jobID
	c1 := d.clientFor(t, "agent:r1")
	c2 := d.clientFor(t, "agent:r2")
	// Первая получает, вторая ещё нет.
	if jobs := d.checkinJobs(t, c1); len(jobs) != 1 {
		t.Fatalf("первой цели не отдали задание: %d", len(jobs))
	}
	if jobs := d.checkinJobs(t, c2); len(jobs) != 0 {
		t.Fatalf("вторая цель получила задание раньше успеха первой: %d", len(jobs))
	}
	// Первая отчиталась успехом → группа 2 (10 % от 3 = 1) открывается.
	if _, err := st.RecordJobResult(ctx, d.jobID, "agent:r1", true, "ок", nil, nil, ActorAgentAPI); err != nil {
		t.Fatalf("результат r1: %v", err)
	}
	if jobs := d.checkinJobs(t, c2); len(jobs) != 1 {
		t.Fatalf("вторая цель не получила задание после успеха первой: %d", len(jobs))
	}
}

func (d *dispatchEnv) clientFor(t *testing.T, cn string) *http.Client {
	t.Helper()
	certPEM, _, priv := d.e.enrollAgent(cn, "ПК", nil)
	return certClient(pemDER(t, certPEM), priv)
}

// job-result: результат до выдачи — 409; успех — 200; повторный —
// 409; неизвестное задание — 404; битое тело — 400.
func TestJobResultEndpoint(t *testing.T) {
	d := newDispatchEnv(t, false)
	cl := d.agent(t, "agent:dispatch")
	_, versionID, _ := d.signedScript(t, gate.KindCatalog, gate.CategoryGeneral, time.Now().Add(24*time.Hour))
	d.makeJob(t, versionID, []string{"agent:dispatch"})

	job := strconv.FormatInt(d.jobID, 10)
	post := func(jobID, body string) int {
		code, _ := d.e.post(cl, d.e.mtlsURL("/agent/v1/jobs/"+jobID+"/result"), []byte(body))
		return code
	}
	if code := post(job, `{"ok":true}`); code != http.StatusConflict {
		t.Fatalf("результат без выдачи: код %d", code)
	}
	if jobs := d.checkinJobs(t, cl); len(jobs) != 1 {
		t.Fatalf("задание не выдано: %d", len(jobs))
	}
	if code := post(job, `{"ok":true,"detail":"готово"}`); code != http.StatusOK {
		t.Fatalf("результат: код %d", code)
	}
	if code := post(job, `{"ok":true}`); code != http.StatusConflict {
		t.Fatalf("повторный результат: код %d", code)
	}
	if code := post("999", `{"ok":true}`); code != http.StatusNotFound {
		t.Fatalf("неизвестное задание: код %d", code)
	}
	if code := post(job, `{"ok":"да"}`); code != http.StatusBadRequest {
		t.Fatalf("битое тело: код %d", code)
	}
	// Нечисловой id пути — 400.
	if code := post("abc", `{"ok":true}`); code != http.StatusBadRequest {
		t.Fatalf("нечисловой id: код %d", code)
	}
}

// shaOf — хэш содержимого версии.
func shaOf(t *testing.T, st *store.Store, scriptID, versionID int64) string {
	t.Helper()
	v, err := st.VersionContent(t.Context(), scriptID, versionID)
	if err != nil {
		t.Fatalf("версия: %v", err)
	}
	return v.SHA256
}
