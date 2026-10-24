// Маршруты владельца для конвейера скриптов (NR-011): репозиторий,
// версии, статусы, проверки, подпись, задания. Подпись — отдельное
// действие владельца с подтверждением вводом имени и хэша; маршрута
// «ставить signed» у смены статуса нет. Всё пишется в аудит.
package api

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/ShkodnikAI/NetAtlas/pipeline/catalog"
	"github.com/ShkodnikAI/NetAtlas/pipeline/checks"
	"github.com/ShkodnikAI/NetAtlas/pipeline/gate"
	"github.com/ShkodnikAI/NetAtlas/pki"
	"github.com/ShkodnikAI/NetAtlas/server/signing"
	"github.com/ShkodnikAI/NetAtlas/server/store"
)

// ScriptsConfig — конфигурация конвейера скриптов для API:
// каталог ключей для подписи владельца (NETATLAS_KEYDIR).
type ScriptsConfig struct {
	KeyDir string
}

// ConfigureScripts подключает подпись скриптов: без каталога ключей
// маршрут подписи отвечает 503 (подписать невозможно честно).
func (a *API) ConfigureScripts(cfg ScriptsConfig) {
	a.scriptKeyDir = cfg.KeyDir
}

// maxJobsBody — предел тела создания задания.
const maxJobsBody = 64 << 10

// failScripts — маппинг ошибок конвейера в коды ответов.
func failScripts(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeJSON(w, http.StatusNotFound, errorBody{"не найдено"})
	case errors.Is(err, store.ErrScriptValue):
		writeJSON(w, http.StatusBadRequest, errorBody{err.Error()})
	case errors.Is(err, store.ErrScriptState):
		writeJSON(w, http.StatusConflict, errorBody{err.Error()})
	default:
		writeJSON(w, http.StatusInternalServerError, errorBody{"внутренняя ошибка"})
	}
}

// pathID — числовой сегмент пути; не число — false.
func pathID(raw string) (int64, bool) {
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || id <= 0 {
		return 0, false
	}
	return id, true
}

// handleScriptsList — GET /api/scripts: список скриптов с последними
// версиями и счётчиками этапов конвейера.
func (a *API) handleScriptsList(w http.ResponseWriter, r *http.Request) {
	scripts, versions, err := a.store.ListScripts(r.Context())
	if err != nil {
		failScripts(w, err)
		return
	}
	stages, err := a.store.StageCounts(r.Context())
	if err != nil {
		failScripts(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"scripts":  scripts,
		"versions": versions,
		"stages":   stages,
	})
}

// handleCatalog — GET /api/catalog: шаблоны каталога действий
// (с схемами параметров, без тел скриптов).
func (a *API) handleCatalog(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"templates": catalog.All()})
}

// createScriptBody — тело POST /api/scripts. Для каталога — ключ
// шаблона и параметры; для произвольного скрипта — текст (всегда
// создаётся draft; «из текста рекомендации» — тот же маршрут).
type createScriptBody struct {
	Name       string            `json:"name"`
	Kind       string            `json:"kind"`
	Category   string            `json:"category"`
	CatalogKey string            `json:"catalog_key,omitempty"`
	Content    string            `json:"content,omitempty"`
	Params     map[string]string `json:"params,omitempty"`
}

// handleScriptCreate — POST /api/scripts: черновик (версия 1, draft).
func (a *API) handleScriptCreate(w http.ResponseWriter, r *http.Request) {
	var body createScriptBody
	if err := decodeJSON(r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{err.Error()})
		return
	}
	if body.Category == "" {
		body.Category = gate.CategoryGeneral
	}
	scriptID, versionID, err := a.store.CreateScript(r.Context(), store.CreateScriptInput{
		Name: body.Name, Kind: body.Kind, Category: body.Category,
		CatalogKey: body.CatalogKey, Content: body.Content, Params: body.Params,
	}, ActorOwner)
	if err != nil {
		failScripts(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]int64{"script_id": scriptID, "version_id": versionID})
}

// handleScriptCard — GET /api/scripts/{id}: скрипт, версии, проверки,
// подписи (без содержимого; содержимое — отдельным маршрутом).
func (a *API) handleScriptCard(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r.PathValue("id"))
	if !ok {
		writeJSON(w, http.StatusBadRequest, errorBody{"id: число"})
		return
	}
	sc, versions, checksMap, sigMap, err := a.store.ScriptCard(r.Context(), id)
	if err != nil {
		failScripts(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"script":     sc,
		"versions":   versions,
		"checks":     checksMap,
		"signatures": sigMap,
	})
}

// handleScriptVersion — GET /api/scripts/{id}/versions/{vid}:
// содержимое версии (просмотр кода).
func (a *API) handleScriptVersion(w http.ResponseWriter, r *http.Request) {
	id, okID := pathID(r.PathValue("id"))
	vid, okV := pathID(r.PathValue("vid"))
	if !okID || !okV {
		writeJSON(w, http.StatusBadRequest, errorBody{"id: число"})
		return
	}
	v, err := a.store.VersionContent(r.Context(), id, vid)
	if err != nil {
		failScripts(w, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

// newVersionBody — тело POST /api/scripts/{id}/versions.
type newVersionBody struct {
	Content    string            `json:"content,omitempty"`
	CatalogKey string            `json:"catalog_key,omitempty"`
	Params     map[string]string `json:"params,omitempty"`
}

// handleScriptNewVersion — POST /api/scripts/{id}/versions: новая
// версия всегда draft (изменение скрипта сбрасывает конвейер).
func (a *API) handleScriptNewVersion(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r.PathValue("id"))
	if !ok {
		writeJSON(w, http.StatusBadRequest, errorBody{"id: число"})
		return
	}
	var body newVersionBody
	if err := decodeJSON(r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{err.Error()})
		return
	}
	// Тип и категория наследуются от скрипта: изменение содержимого
	// не меняет тип (catalog рендерится по шаблону).
	sc, _, _, _, err := a.store.ScriptCard(r.Context(), id)
	if err != nil {
		failScripts(w, err)
		return
	}
	versionID, err := a.store.CreateVersion(r.Context(), id, store.CreateScriptInput{
		Name: sc.Name, Kind: sc.Kind, Category: sc.Category,
		CatalogKey: body.CatalogKey, Content: body.Content, Params: body.Params,
	}, ActorOwner)
	if err != nil {
		failScripts(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]int64{"version_id": versionID})
}

// statusBody — тело POST .../status: переход вперёд по цепочке или
// rejected, с комментарием (ручная отметка требует причины).
type statusBody struct {
	To      string `json:"to"`
	Comment string `json:"comment"`
}

// handleScriptStatus — POST .../status. Статус signed этим маршрутом
// не ставится: store отвергает (подпись — отдельное действие).
func (a *API) handleScriptStatus(w http.ResponseWriter, r *http.Request) {
	id, okID := pathID(r.PathValue("id"))
	vid, okV := pathID(r.PathValue("vid"))
	if !okID || !okV {
		writeJSON(w, http.StatusBadRequest, errorBody{"id: число"})
		return
	}
	var body statusBody
	if err := decodeJSON(r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{err.Error()})
		return
	}
	v, err := a.store.AdvanceStatus(r.Context(), id, vid, body.To, body.Comment, ActorOwner)
	if err != nil {
		failScripts(w, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

// checkResultBody — тело POST .../check-result: запись результата
// проверки или теста ВМ. Стенд шлёт source=stand; ручная отметка —
// source=manual с обязательным комментарием.
type checkResultBody struct {
	Kind    string `json:"kind"`   // static | vm
	Source  string `json:"source"` // stand | manual
	Result  string `json:"result"` // pass | fail
	Detail  string `json:"detail,omitempty"`
	Comment string `json:"comment,omitempty"`
}

// handleCheckResult — POST .../check-result: результат из стенда
// (NR-026) или ручная отметка владельца. Проходной результат
// переводит статус через gate. Локальный источник server сюда не
// принимает: он возникает только из check-run.
func (a *API) handleCheckResult(w http.ResponseWriter, r *http.Request) {
	id, okID := pathID(r.PathValue("id"))
	vid, okV := pathID(r.PathValue("vid"))
	if !okID || !okV {
		writeJSON(w, http.StatusBadRequest, errorBody{"id: число"})
		return
	}
	var body checkResultBody
	if err := decodeJSON(r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{err.Error()})
		return
	}
	if body.Source == "server" {
		writeJSON(w, http.StatusBadRequest, errorBody{"источник server ставится только запуском проверки на сервере"})
		return
	}
	actor := "stand"
	if body.Source == "manual" {
		actor = ActorOwner
	}
	v, err := a.store.RecordCheck(r.Context(), id, vid, store.CheckRow{
		Kind: body.Kind, Source: body.Source, Detail: body.Detail, Comment: body.Comment, Actor: actor,
	}, body.Result == "pass")
	if err != nil {
		failScripts(w, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

// handleCheckRun — POST .../check-run: серверный запуск статических
// проверок. Если pwsh или PSScriptAnalyzer недоступны — 503: стадия
// «проверен» ставится только результатом стенда или ручной отметкой.
func (a *API) handleCheckRun(w http.ResponseWriter, r *http.Request) {
	id, okID := pathID(r.PathValue("id"))
	vid, okV := pathID(r.PathValue("vid"))
	if !okID || !okV {
		writeJSON(w, http.StatusBadRequest, errorBody{"id: число"})
		return
	}
	v, err := a.store.VersionContent(r.Context(), id, vid)
	if err != nil {
		failScripts(w, err)
		return
	}
	report, err := checks.Analyze(r.Context(), v.Content, nil)
	if err != nil {
		if errors.Is(err, checks.ErrUnavailable) {
			writeJSON(w, http.StatusServiceUnavailable, errorBody{
				"статические проверки недоступны на сервере (нужен pwsh с PSScriptAnalyzer): результат можно записать со стенда или вручную с комментарием",
			})
			return
		}
		writeJSON(w, http.StatusInternalServerError, errorBody{"запуск проверок"})
		return
	}
	detail, err := json.Marshal(report)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorBody{"сводка проверок"})
		return
	}
	updated, err := a.store.RecordCheck(r.Context(), id, vid, store.CheckRow{
		Kind: "static", Source: "server", Detail: string(detail), Actor: "server",
	}, report.OK)
	if err != nil {
		failScripts(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"report": report, "version": updated})
}

// signBody — тело POST .../sign: подтверждение вводом имени скрипта
// и хэша. Сервер сверяет оба значения с хранимыми.
type signBody struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
}

// handleSign — POST .../sign: подпись владельца. Ключ читается из
// NETATLAS_KEYDIR в момент подписания; без каталога ключей — 503.
// Имя и хэш должны совпасть с хранимыми — подписывается именно то
// содержимое, которое владелец видел на экране.
func (a *API) handleSign(w http.ResponseWriter, r *http.Request) {
	id, okID := pathID(r.PathValue("id"))
	vid, okV := pathID(r.PathValue("vid"))
	if !okID || !okV {
		writeJSON(w, http.StatusBadRequest, errorBody{"id: число"})
		return
	}
	var body signBody
	if err := decodeJSON(r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{err.Error()})
		return
	}
	if a.scriptKeyDir == "" {
		writeJSON(w, http.StatusServiceUnavailable, errorBody{
			"подпись недоступна: NETATLAS_KEYDIR не задан на сервере",
		})
		return
	}
	sc, versions, _, _, err := a.store.ScriptCard(r.Context(), id)
	if err != nil {
		failScripts(w, err)
		return
	}
	if sc.Name != body.Name {
		writeJSON(w, http.StatusBadRequest, errorBody{"имя скрипта не совпадает"})
		return
	}
	var version *store.VersionRow
	for i := range versions {
		if versions[i].ID == vid {
			version = &versions[i]
			break
		}
	}
	if version == nil {
		writeJSON(w, http.StatusNotFound, errorBody{"версия не найдена"})
		return
	}
	sha := normalizeHex(body.SHA256)
	if sha == "" || sha != version.SHA256 {
		writeJSON(w, http.StatusBadRequest, errorBody{"хэш не совпадает с версией"})
		return
	}
	key, err := pki.LoadSigningKey(a.scriptKeyDir)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, errorBody{"ключ подписи не читается"})
		return
	}
	shaBytes, err := hex.DecodeString(sha)
	if err != nil || len(shaBytes) != signing.NonceSize {
		writeJSON(w, http.StatusBadRequest, errorBody{"хэш: 64 hex-символа"})
		return
	}
	expires := time.Now().Add(store.ScriptSignValidity)
	sig, err := signing.SignScript(shaBytes, expires, key)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorBody{"подпись"})
		return
	}
	updated, err := a.store.SignVersion(r.Context(), id, vid, sha,
		base64.StdEncoding.EncodeToString(sig), expires, ActorOwner)
	if err != nil {
		failScripts(w, err)
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

// normalizeHex — нижний регистр и без разделителей; не hex — пусто.
func normalizeHex(s string) string {
	var out []rune
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f':
			out = append(out, c)
		case c >= 'A' && c <= 'F':
			out = append(out, c+32)
		case c == ' ' || c == ':' || c == '-':
		default:
			return ""
		}
	}
	if len(out) != 64 {
		return ""
	}
	return string(out)
}

// createJobBody — тело POST /api/jobs.
type createJobBody struct {
	ScriptVersionID int64    `json:"script_version_id"`
	Targets         []string `json:"targets"`
	Pilot           bool     `json:"pilot,omitempty"`
	WindowStart     string   `json:"window_start,omitempty"`
	WindowEnd       string   `json:"window_end,omitempty"`
	Deadline        string   `json:"deadline,omitempty"`
	MetricThreshold float64  `json:"metric_threshold,omitempty"`
}

// handleJobCreate — POST /api/jobs: создание задания (цель, окно
// времени, срок). Задание попадёт агентам только через шлюз.
func (a *API) handleJobCreate(w http.ResponseWriter, r *http.Request) {
	var body createJobBody
	r.Body = http.MaxBytesReader(w, r.Body, maxJobsBody)
	if err := decodeJSON(r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{err.Error()})
		return
	}
	for _, ts := range []string{body.WindowStart, body.WindowEnd, body.Deadline} {
		if ts != "" {
			if _, err := time.Parse(time.RFC3339, ts); err != nil {
				writeJSON(w, http.StatusBadRequest, errorBody{"время: формат RFC3339"})
				return
			}
		}
	}
	jobID, err := a.store.CreateJob(r.Context(), store.CreateJobInput{
		ScriptVersionID: body.ScriptVersionID, Targets: body.Targets, Pilot: body.Pilot,
		WindowStart: body.WindowStart, WindowEnd: body.WindowEnd, Deadline: body.Deadline,
		MetricThreshold: body.MetricThreshold,
	}, ActorOwner)
	if err != nil {
		failScripts(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]int64{"id": jobID})
}

// handleJobsList — GET /api/jobs?version_id=: список заданий.
func (a *API) handleJobsList(w http.ResponseWriter, r *http.Request) {
	var versionID int64
	if raw := r.URL.Query().Get("version_id"); raw != "" {
		id, ok := pathID(raw)
		if !ok {
			writeJSON(w, http.StatusBadRequest, errorBody{"version_id: число"})
			return
		}
		versionID = id
	}
	jobs, err := a.store.ListJobs(r.Context(), versionID)
	if err != nil {
		failScripts(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"jobs": jobs})
}

// handleJob — GET /api/jobs/{id}: задание с целями.
func (a *API) handleJob(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r.PathValue("id"))
	if !ok {
		writeJSON(w, http.StatusBadRequest, errorBody{"id: число"})
		return
	}
	job, err := a.store.JobByID(r.Context(), id)
	if err != nil {
		failScripts(w, err)
		return
	}
	writeJSON(w, http.StatusOK, job)
}

// stopBody — тело POST /api/jobs/{id}/stop.
type stopBody struct {
	Reason string `json:"reason,omitempty"`
}

// handleJobStop — POST /api/jobs/{id}/stop: остановка задания
// владельцем (остальные queued-цели снимаются).
func (a *API) handleJobStop(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r.PathValue("id"))
	if !ok {
		writeJSON(w, http.StatusBadRequest, errorBody{"id: число"})
		return
	}
	var body stopBody
	if r.Body != nil {
		if err := decodeJSON(r, &body); err != nil {
			writeJSON(w, http.StatusBadRequest, errorBody{err.Error()})
			return
		}
	}
	if err := a.store.StopJob(r.Context(), id, body.Reason, ActorOwner); err != nil {
		failScripts(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
