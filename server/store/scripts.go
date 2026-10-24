// Скрипты и версии (NR-011): репозиторий скриптов, статусы конвейера
// (переходы только через pipeline/gate), результаты проверок и тестов,
// подписи владельца на хэш содержимого. Изменяющие операции пишут
// аудит в своей транзакции; маршрута «подписать» вне владельческого
// действия не существует.
package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/ShkodnikAI/NetAtlas/pipeline/catalog"
	"github.com/ShkodnikAI/NetAtlas/pipeline/gate"
	"github.com/ShkodnikAI/NetAtlas/server/audit"
)

// catalogGet — шаблон каталога (обёртка для читаемости store).
func catalogGet(key string) (catalog.Template, error) { return catalog.Get(key) }

// Границы значений репозитория скриптов.
const (
	MaxScriptNameLen    = 200
	MaxScriptContentLen = 256 << 10 // 256 КБ текста скрипта
	MaxScriptCommentLen = 2000
	MaxScriptDetailLen  = 4000
	// MaxTestRunLogBytes — предел журнала теста со стенда.
	MaxTestRunLogBytes = 256 << 10
	// ScriptSignValidity — срок подписи владельца: задание, выданное
	// позже, не отдаётся и помечается expired.
	ScriptSignValidity = 30 * 24 * time.Hour
)

// Ошибки репозитория скриптов (API отображает в коды ответов).
var (
	// ErrScriptState — недопустимый переход статуса или состояние
	// не позволяет действие (подпись без теста, повторная подпись
	// не того содержимого и т.п.).
	ErrScriptState = errors.New("store: действие недопустимо в этом статусе")
	// ErrScriptValue — неверные входные значения (имя, параметры, тело).
	ErrScriptValue = errors.New("store: неверные значения скрипта")
)

// ScriptRow — карточка скрипта без содержимого версий.
type ScriptRow struct {
	ID         int64  `json:"id"`
	Name       string `json:"name"`
	Kind       string `json:"kind"`
	Category   string `json:"category"`
	CatalogKey string `json:"catalog_key,omitempty"`
	CreatedAt  string `json:"created_at"`
	UpdatedAt  string `json:"updated_at"`
}

// VersionRow — версия скрипта. Содержимое отдаётся по запросу одной
// версии, в списках — только хэш.
type VersionRow struct {
	ID        int64  `json:"id"`
	ScriptID  int64  `json:"script_id"`
	Version   int64  `json:"version"`
	Status    string `json:"status"`
	SHA256    string `json:"sha256"`
	Params    string `json:"params,omitempty"`
	PilotOK   bool   `json:"pilot_ok"`
	CreatedAt string `json:"created_at"`
}

// VersionFull — версия с содержимым (карточка, просмотр кода).
type VersionFull struct {
	VersionRow
	Content string `json:"content"`
}

// CheckRow — результат проверки или теста.
type CheckRow struct {
	ID      int64  `json:"id"`
	Kind    string `json:"kind"`   // static | vm
	Source  string `json:"source"` // stand | server | manual
	Result  string `json:"result"` // pass | fail
	Detail  string `json:"detail,omitempty"`
	Comment string `json:"comment,omitempty"`
	RanAt   string `json:"ran_at"`
	Actor   string `json:"actor"`
	// Log — журнал теста со стенда (NR-026): недоверенный текст,
	// до 256 КБ; для остальных источников пустой.
	Log string `json:"log,omitempty"`
}

// SignatureRow — подпись владельца версии.
type SignatureRow struct {
	ID        int64  `json:"id"`
	SHA256    string `json:"sha256"`
	SignedBy  string `json:"signed_by"`
	SignedAt  string `json:"signed_at"`
	ExpiresAt string `json:"expires_at"`
	Signature string `json:"signature"`
}

// CreateScriptInput — вход создания скрипта. Для kind=catalog
// CatalogKey — ключ шаблона, Params — параметры (содержимое
// рендерится из шаблона); для kind=script Content — текст скрипта.
type CreateScriptInput struct {
	Name       string
	Kind       string
	Category   string
	CatalogKey string
	Content    string
	Params     map[string]string
}

// CreateScript создаёт скрипт и версию 1 в статусе draft. Содержимое
// для каталога рендерится шаблоном с валидацией параметров: значение
// вне схемы не попадает в скрипт.
func (s *Store) CreateScript(ctx context.Context, in CreateScriptInput, actor string) (int64, int64, error) {
	if err := validateScriptInput(in); err != nil {
		return 0, 0, err
	}
	content, params := in.Content, ""
	var catalogKey string
	switch in.Kind {
	case gate.KindCatalog:
		tpl, err := catalogGet(in.CatalogKey)
		if err != nil {
			return 0, 0, fmt.Errorf("%w: %v", ErrScriptValue, err)
		}
		catalogKey = in.CatalogKey
		var errRender error
		content, errRender = tpl.Render(in.Params)
		if errRender != nil {
			return 0, 0, fmt.Errorf("%w: %v", ErrScriptValue, errRender)
		}
		raw, err := json.Marshal(in.Params)
		if err != nil {
			return 0, 0, fmt.Errorf("%w: параметры: %v", ErrScriptValue, err)
		}
		params = string(raw)
	default: // kind=script
		if len(content) == 0 || len(content) > MaxScriptContentLen {
			return 0, 0, fmt.Errorf("%w: пустое или слишком длинное содержимое", ErrScriptValue)
		}
	}
	sum := sha256.Sum256([]byte(content))
	sha := hex.EncodeToString(sum[:])
	now := time.Now().UTC().Format(time.RFC3339Nano)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, 0, fmt.Errorf("store: транзакция создания скрипта: %w", err)
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx,
		`INSERT INTO scripts (name, kind, category, catalog_key, created_at, updated_at)
                 VALUES (?, ?, ?, ?, ?, ?)`,
		in.Name, in.Kind, in.Category, catalogKey, now, now)
	if err != nil {
		return 0, 0, fmt.Errorf("store: скрипт: %w", err)
	}
	scriptID, err := res.LastInsertId()
	if err != nil {
		return 0, 0, fmt.Errorf("store: скрипт: id: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO script_versions (script_id, version, status, content, sha256, params, created_at)
                 VALUES (?, 1, ?, ?, ?, ?, ?)`,
		scriptID, gate.StatusDraft, content, sha, params, now); err != nil {
		return 0, 0, fmt.Errorf("store: версия 1: %w", err)
	}
	versionID, err := resVersion(ctx, tx, scriptID)
	if err != nil {
		return 0, 0, err
	}
	detail, err := json.Marshal(map[string]any{
		"name": in.Name, "kind": in.Kind, "category": in.Category, "sha256": shortSHA(sha),
	})
	if err != nil {
		return 0, 0, fmt.Errorf("store: сводка создания скрипта: %w", err)
	}
	if _, err := audit.Append(ctx, tx, audit.Entry{
		Actor: actor, Action: "script_create", Target: in.Name, Result: "ok", Detail: string(detail),
	}); err != nil {
		return 0, 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, 0, fmt.Errorf("store: фиксация скрипта: %w", err)
	}
	return scriptID, versionID, nil
}

// resVersion — id вставленной версии 1 (по уникальной паре).
func resVersion(ctx context.Context, tx *sql.Tx, scriptID int64) (int64, error) {
	var id int64
	err := tx.QueryRowContext(ctx,
		`SELECT id FROM script_versions WHERE script_id = ? AND version = 1`, scriptID).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("store: версия 1: id: %w", err)
	}
	return id, nil
}

// CreateVersion добавляет версию скрипта (изменение содержимого):
// новая версия всегда draft — изменение скрипта сбрасывает конвейер.
func (s *Store) CreateVersion(ctx context.Context, scriptID int64, in CreateScriptInput, actor string) (int64, error) {
	if err := validateScriptInput(in); err != nil {
		return 0, err
	}
	content := in.Content
	params := ""
	if in.Kind == gate.KindCatalog {
		tpl, err := catalogGet(in.CatalogKey)
		if err != nil {
			return 0, fmt.Errorf("%w: %v", ErrScriptValue, err)
		}
		var errRender error
		content, errRender = tpl.Render(in.Params)
		if errRender != nil {
			return 0, fmt.Errorf("%w: %v", ErrScriptValue, errRender)
		}
		raw, err := json.Marshal(in.Params)
		if err != nil {
			return 0, fmt.Errorf("%w: параметры: %v", ErrScriptValue, err)
		}
		params = string(raw)
	} else if len(content) == 0 || len(content) > MaxScriptContentLen {
		return 0, fmt.Errorf("%w: пустое или слишком длинное содержимое", ErrScriptValue)
	}
	sum := sha256.Sum256([]byte(content))
	sha := hex.EncodeToString(sum[:])
	now := time.Now().UTC().Format(time.RFC3339Nano)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("store: транзакция версии: %w", err)
	}
	defer tx.Rollback()
	var name, kind string
	err = tx.QueryRowContext(ctx, `SELECT name, kind FROM scripts WHERE id = ?`, scriptID).Scan(&name, &kind)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrNotFound
	}
	if err != nil {
		return 0, fmt.Errorf("store: скрипт %d: %w", scriptID, err)
	}
	if kind != in.Kind {
		return 0, fmt.Errorf("%w: тип скрипта менять нельзя", ErrScriptValue)
	}
	var maxVersion sql.NullInt64
	if err := tx.QueryRowContext(ctx,
		`SELECT MAX(version) FROM script_versions WHERE script_id = ?`, scriptID).Scan(&maxVersion); err != nil {
		return 0, fmt.Errorf("store: версии скрипта %d: %w", scriptID, err)
	}
	next := maxVersion.Int64 + 1
	res, err := tx.ExecContext(ctx,
		`INSERT INTO script_versions (script_id, version, status, content, sha256, params, created_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		scriptID, next, gate.StatusDraft, content, sha, params, now)
	if err != nil {
		return 0, fmt.Errorf("store: версия %d: %w", next, err)
	}
	versionID, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("store: версия: id: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE scripts SET updated_at = ? WHERE id = ?`, now, scriptID); err != nil {
		return 0, fmt.Errorf("store: скрипт %d: отметка времени: %w", scriptID, err)
	}
	detail, err := json.Marshal(map[string]any{"version": next, "sha256": shortSHA(sha)})
	if err != nil {
		return 0, fmt.Errorf("store: сводка версии: %w", err)
	}
	if _, err := audit.Append(ctx, tx, audit.Entry{
		Actor: actor, Action: "script_version_create", Target: name, Result: "ok", Detail: string(detail),
	}); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("store: фиксация версии: %w", err)
	}
	return versionID, nil
}

// ListScripts — все скрипты с последней версией и её статусом.
func (s *Store) ListScripts(ctx context.Context) ([]ScriptRow, []VersionRow, error) {
	rows, err := s.db.QueryContext(ctx, `
                SELECT s.id, s.name, s.kind, s.category, s.catalog_key, s.created_at, s.updated_at,
                       v.id, v.version, v.status, v.sha256, v.pilot_ok, v.created_at
                FROM scripts s
                JOIN script_versions v ON v.id = (
                        SELECT id FROM script_versions WHERE script_id = s.id ORDER BY version DESC LIMIT 1)
                ORDER BY s.id`)
	if err != nil {
		return nil, nil, fmt.Errorf("store: список скриптов: %w", err)
	}
	defer rows.Close()
	scripts := []ScriptRow{}
	versions := []VersionRow{}
	for rows.Next() {
		var sc ScriptRow
		var v VersionRow
		var pilot int
		if err := rows.Scan(&sc.ID, &sc.Name, &sc.Kind, &sc.Category, &sc.CatalogKey, &sc.CreatedAt, &sc.UpdatedAt,
			&v.ID, &v.Version, &v.Status, &v.SHA256, &pilot, &v.CreatedAt); err != nil {
			return nil, nil, fmt.Errorf("store: список скриптов: строка: %w", err)
		}
		v.ScriptID, v.PilotOK = sc.ID, pilot == 1
		scripts = append(scripts, sc)
		versions = append(versions, v)
	}
	return scripts, versions, rows.Err()
}

// ScriptCard — карточка скрипта: сам скрипт, все версии (без
// содержимого), для каждой версии — проверки и последняя подпись.
func (s *Store) ScriptCard(ctx context.Context, id int64) (ScriptRow, []VersionRow, map[int64][]CheckRow, map[int64]SignatureRow, error) {
	var sc ScriptRow
	err := s.db.QueryRowContext(ctx,
		`SELECT id, name, kind, category, catalog_key, created_at, updated_at FROM scripts WHERE id = ?`, id).
		Scan(&sc.ID, &sc.Name, &sc.Kind, &sc.Category, &sc.CatalogKey, &sc.CreatedAt, &sc.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return ScriptRow{}, nil, nil, nil, ErrNotFound
	}
	if err != nil {
		return ScriptRow{}, nil, nil, nil, fmt.Errorf("store: скрипт %d: %w", id, err)
	}
	versions, err := s.listVersions(ctx, id)
	if err != nil {
		return ScriptRow{}, nil, nil, nil, err
	}
	checksMap := map[int64][]CheckRow{}
	for _, v := range versions {
		runs, err := s.listChecks(ctx, v.ID)
		if err != nil {
			return ScriptRow{}, nil, nil, nil, err
		}
		checksMap[v.ID] = runs
	}
	sigMap := map[int64]SignatureRow{}
	for _, v := range versions {
		sig, err := s.latestSignature(ctx, v.ID)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return ScriptRow{}, nil, nil, nil, err
		}
		if err == nil {
			sigMap[v.ID] = sig
		}
	}
	return sc, versions, checksMap, sigMap, nil
}

// VersionContent — одна версия с содержимым (просмотр кода).
func (s *Store) VersionContent(ctx context.Context, scriptID, versionID int64) (VersionFull, error) {
	var v VersionFull
	var pilot int
	var params sql.NullString
	err := s.db.QueryRowContext(ctx, `
                SELECT v.id, v.script_id, v.version, v.status, v.sha256, v.pilot_ok, v.created_at, v.content, v.params
                FROM script_versions v WHERE v.id = ? AND v.script_id = ?`, versionID, scriptID).
		Scan(&v.ID, &v.ScriptID, &v.Version, &v.Status, &v.SHA256, &pilot, &v.CreatedAt, &v.Content, &params)
	if errors.Is(err, sql.ErrNoRows) {
		return VersionFull{}, ErrNotFound
	}
	if err != nil {
		return VersionFull{}, fmt.Errorf("store: версия %d: %w", versionID, err)
	}
	v.PilotOK, v.Params = pilot == 1, params.String
	return v, nil
}

// AdvanceStatus — смена статуса владельцем: переход только вперёд
// по цепочке или в rejected, только через gate.CanAdvance. Ручная
// отметка требует комментария и пишется в аудит. Статус signed
// этим маршрутом не ставится никогда: подпись — отдельное действие
// владельца (SignVersion).
func (s *Store) AdvanceStatus(ctx context.Context, scriptID, versionID int64, to, comment, actor string) (VersionRow, error) {
	if !gate.IsStatus(to) {
		return VersionRow{}, fmt.Errorf("%w: неизвестный статус %q", ErrScriptValue, to)
	}
	if to == gate.StatusSigned {
		// Защита маршрута: в signed ведёт только действие подписи.
		return VersionRow{}, fmt.Errorf("%w: статус «подписан» ставится только действием подписи владельца", ErrScriptState)
	}
	if len(comment) == 0 || len(comment) > MaxScriptCommentLen {
		return VersionRow{}, fmt.Errorf("%w: ручная отметка требует комментария", ErrScriptValue)
	}
	if actor == "" {
		return VersionRow{}, fmt.Errorf("%w: актор не задан", ErrScriptValue)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return VersionRow{}, fmt.Errorf("store: транзакция статуса: %w", err)
	}
	defer tx.Rollback()
	v, name, err := versionForUpdate(ctx, tx, scriptID, versionID)
	if err != nil {
		return VersionRow{}, err
	}
	if err := gate.CanAdvance(v.Status, to); err != nil {
		return VersionRow{}, fmt.Errorf("%w: %v", ErrScriptState, err)
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE script_versions SET status = ? WHERE id = ?`, to, versionID); err != nil {
		return VersionRow{}, fmt.Errorf("store: версия %d: статус: %w", versionID, err)
	}
	// Ручная отметка проверки: зафиксировать, кто и почему перевёл.
	var runKind string
	switch to {
	case gate.StatusChecked:
		runKind = "static"
	case gate.StatusTested:
		runKind = "vm"
	}
	if runKind != "" {
		if _, err := tx.ExecContext(ctx, `
                        INSERT INTO test_runs (script_version_id, kind, source, result, comment, ran_at, actor)
                        VALUES (?, ?, 'manual', 'pass', ?, ?, ?)`,
			versionID, runKind, comment, time.Now().UTC().Format(time.RFC3339Nano), actor); err != nil {
			return VersionRow{}, fmt.Errorf("store: ручная отметка: %w", err)
		}
	}
	detail, err := json.Marshal(map[string]any{
		"version": v.Version, "from": v.Status, "to": to, "comment": comment,
	})
	if err != nil {
		return VersionRow{}, fmt.Errorf("store: сводка статуса: %w", err)
	}
	if _, err := audit.Append(ctx, tx, audit.Entry{
		Actor: actor, Action: "script_status", Target: name, Result: "ok", Detail: string(detail),
	}); err != nil {
		return VersionRow{}, err
	}
	if err := tx.Commit(); err != nil {
		return VersionRow{}, fmt.Errorf("store: фиксация статуса: %w", err)
	}
	v.Status = to
	return v, nil
}

// RecordCheck — запись результата проверки/теста. Источник: stand
// (стенд Hyper-V, NR-026), server (локальный запуск проверок),
// manual (ручная отметка — комментарий обязателен). Проходной
// результат переводит статус: static pass → checked, vm pass →
// tested — через gate.CanAdvance. Указывается актор: стенд действует
// под своей меткой, ручная отметка — от владельца.
func (s *Store) RecordCheck(ctx context.Context, scriptID, versionID int64, in CheckRow, pass bool) (VersionRow, error) {
	if in.Kind != "static" && in.Kind != "vm" {
		return VersionRow{}, fmt.Errorf("%w: вид проверки %q", ErrScriptValue, in.Kind)
	}
	switch in.Source {
	case "stand", "server", "manual":
	default:
		return VersionRow{}, fmt.Errorf("%w: источник %q", ErrScriptValue, in.Source)
	}
	if in.Source == "manual" && (len(in.Comment) == 0 || len(in.Comment) > MaxScriptCommentLen) {
		return VersionRow{}, fmt.Errorf("%w: ручная отметка требует комментария", ErrScriptValue)
	}
	if len(in.Detail) > MaxScriptDetailLen {
		return VersionRow{}, fmt.Errorf("%w: detail длиннее %d", ErrScriptValue, MaxScriptDetailLen)
	}
	if len(in.Log) > MaxTestRunLogBytes {
		return VersionRow{}, fmt.Errorf("%w: журнал теста длиннее %d", ErrScriptValue, MaxTestRunLogBytes)
	}
	if in.Actor == "" {
		return VersionRow{}, fmt.Errorf("%w: актор не задан", ErrScriptValue)
	}
	result := "fail"
	if pass {
		result = "pass"
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return VersionRow{}, fmt.Errorf("store: транзакция проверки: %w", err)
	}
	defer tx.Rollback()
	v, name, err := versionForUpdate(ctx, tx, scriptID, versionID)
	if err != nil {
		return VersionRow{}, err
	}
	if _, err := tx.ExecContext(ctx, `
                INSERT INTO test_runs (script_version_id, kind, source, result, detail, comment, ran_at, actor, log)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		versionID, in.Kind, in.Source, result, in.Detail, in.Comment,
		time.Now().UTC().Format(time.RFC3339Nano), in.Actor, in.Log); err != nil {
		return VersionRow{}, fmt.Errorf("store: запись проверки: %w", err)
	}
	if pass {
		// Проходной результат переводит статус вперёд ровно на один шаг.
		var to string
		if in.Kind == "static" {
			to = gate.StatusChecked
		} else {
			to = gate.StatusTested
		}
		if err := gate.CanAdvance(v.Status, to); err != nil {
			return VersionRow{}, fmt.Errorf("%w: %v", ErrScriptState, err)
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE script_versions SET status = ? WHERE id = ?`, to, versionID); err != nil {
			return VersionRow{}, fmt.Errorf("store: версия %d: статус: %w", versionID, err)
		}
		v.Status = to
	}
	detail, err := json.Marshal(map[string]any{
		"version": v.Version, "kind": in.Kind, "source": in.Source, "result": result,
	})
	if err != nil {
		return VersionRow{}, fmt.Errorf("store: сводка проверки: %w", err)
	}
	if _, err := audit.Append(ctx, tx, audit.Entry{
		Actor: in.Actor, Action: "script_check", Target: name, Result: result, Detail: string(detail),
	}); err != nil {
		return VersionRow{}, err
	}
	if err := tx.Commit(); err != nil {
		return VersionRow{}, fmt.Errorf("store: фиксация проверки: %w", err)
	}
	return v, nil
}

// SignVersion — действие подписи владельца: запись signatures на
// хэш содержимого и перевод статуса tested → signed (только если
// статус ровно tested). sha256 должен совпасть с хэшем версии:
// подписывается то содержимое, которое владелец видел. Криптография
// (ed25519) — у вызывающего (API), здесь запись и статус.
func (s *Store) SignVersion(ctx context.Context, scriptID, versionID int64, sha, signature string, expires time.Time, actor string) (VersionRow, error) {
	if sha == "" || signature == "" {
		return VersionRow{}, fmt.Errorf("%w: подпись без хэша или без подписи", ErrScriptValue)
	}
	if expires.Before(time.Now()) {
		return VersionRow{}, fmt.Errorf("%w: срок подписи в прошлом", ErrScriptValue)
	}
	if actor == "" {
		return VersionRow{}, fmt.Errorf("%w: актор не задан", ErrScriptValue)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return VersionRow{}, fmt.Errorf("store: транзакция подписи: %w", err)
	}
	defer tx.Rollback()
	v, name, err := versionForUpdate(ctx, tx, scriptID, versionID)
	if err != nil {
		return VersionRow{}, err
	}
	if v.SHA256 != sha {
		return VersionRow{}, fmt.Errorf("%w: хэш не совпадает с версией", ErrScriptState)
	}
	if !gate.AtLeast(v.Status, gate.StatusTested) {
		return VersionRow{}, fmt.Errorf("%w: подпись после проверки: статус %q", ErrScriptState, v.Status)
	}
	now := time.Now().UTC()
	if _, err := tx.ExecContext(ctx, `
                INSERT INTO signatures (script_version_id, sha256, signed_by, signed_at, expires_at, signature)
                VALUES (?, ?, ?, ?, ?, ?)`,
		versionID, sha, actor, now.Format(time.RFC3339Nano), expires.UTC().Format(time.RFC3339Nano), signature); err != nil {
		return VersionRow{}, fmt.Errorf("store: подпись: %w", err)
	}
	if v.Status == gate.StatusTested {
		if err := gate.CanAdvance(v.Status, gate.StatusSigned); err != nil {
			return VersionRow{}, fmt.Errorf("%w: %v", ErrScriptState, err)
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE script_versions SET status = ? WHERE id = ?`, gate.StatusSigned, versionID); err != nil {
			return VersionRow{}, fmt.Errorf("store: версия %d: статус: %w", versionID, err)
		}
		v.Status = gate.StatusSigned
	}
	detail, err := json.Marshal(map[string]any{
		"version": v.Version, "sha256": shortSHA(sha), "expires_at": expires.UTC().Format(time.RFC3339),
	})
	if err != nil {
		return VersionRow{}, fmt.Errorf("store: сводка подписи: %w", err)
	}
	if _, err := audit.Append(ctx, tx, audit.Entry{
		Actor: actor, Action: "script_sign", Target: name, Result: "ok", Detail: string(detail),
	}); err != nil {
		return VersionRow{}, err
	}
	if err := tx.Commit(); err != nil {
		return VersionRow{}, fmt.Errorf("store: фиксация подписи: %w", err)
	}
	return v, nil
}

// VersionBySHA256 — версия по хэшу содержимого: результаты со
// стенда приходят с хэшем скрипта (владелец запускает локальный
// файл), связываем с версией без участия клиента. Несколько версий
// с одним содержимым — берём последнюю по времени.
func (s *Store) VersionBySHA256(ctx context.Context, sha string) (int64, int64, error) {
	if len(sha) != 64 {
		return 0, 0, fmt.Errorf("%w: хэш не 64 hex-символа", ErrScriptValue)
	}
	var scriptID, versionID int64
	err := s.db.QueryRowContext(ctx, `
                SELECT script_id, id FROM script_versions WHERE sha256 = ? ORDER BY id DESC LIMIT 1`, sha).
		Scan(&scriptID, &versionID)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, 0, ErrNotFound
	}
	if err != nil {
		return 0, 0, fmt.Errorf("store: версия по хэшу: %w", err)
	}
	return scriptID, versionID, nil
}

// StageCounts — счётчики версий по статусам конвейера (карточки
// этапов на экране).
func (s *Store) StageCounts(ctx context.Context) (map[string]int, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT status, COUNT(*) FROM script_versions GROUP BY status`)
	if err != nil {
		return nil, fmt.Errorf("store: счётчики статусов: %w", err)
	}
	defer rows.Close()
	counts := map[string]int{}
	for rows.Next() {
		var status string
		var n int
		if err := rows.Scan(&status, &n); err != nil {
			return nil, fmt.Errorf("store: счётчики статусов: строка: %w", err)
		}
		counts[status] = n
	}
	return counts, rows.Err()
}

// --- внутренние -------------------------------------------------------------

// versionForUpdate — версия (внутри транзакции) и имя скрипта для
// аудита.
func versionForUpdate(ctx context.Context, tx *sql.Tx, scriptID, versionID int64) (VersionRow, string, error) {
	var v VersionRow
	var pilot int
	var params, name sql.NullString
	err := tx.QueryRowContext(ctx, `
                SELECT v.id, v.script_id, v.version, v.status, v.sha256, v.pilot_ok, v.created_at, v.params,
                       s.name
                FROM script_versions v JOIN scripts s ON s.id = v.script_id
                WHERE v.id = ? AND v.script_id = ?`, versionID, scriptID).
		Scan(&v.ID, &v.ScriptID, &v.Version, &v.Status, &v.SHA256, &pilot, &v.CreatedAt, &params, &name)
	if errors.Is(err, sql.ErrNoRows) {
		return VersionRow{}, "", ErrNotFound
	}
	if err != nil {
		return VersionRow{}, "", fmt.Errorf("store: версия %d: %w", versionID, err)
	}
	v.PilotOK, v.Params = pilot == 1, params.String
	return v, name.String, nil
}

func (s *Store) listVersions(ctx context.Context, scriptID int64) ([]VersionRow, error) {
	rows, err := s.db.QueryContext(ctx, `
                SELECT id, script_id, version, status, sha256, params, pilot_ok, created_at
                FROM script_versions WHERE script_id = ? ORDER BY version DESC`, scriptID)
	if err != nil {
		return nil, fmt.Errorf("store: версии скрипта %d: %w", scriptID, err)
	}
	defer rows.Close()
	out := []VersionRow{}
	for rows.Next() {
		var v VersionRow
		var pilot int
		var params sql.NullString
		if err := rows.Scan(&v.ID, &v.ScriptID, &v.Version, &v.Status, &v.SHA256, &params, &pilot, &v.CreatedAt); err != nil {
			return nil, fmt.Errorf("store: версии скрипта %d: строка: %w", scriptID, err)
		}
		v.PilotOK, v.Params = pilot == 1, params.String
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *Store) listChecks(ctx context.Context, versionID int64) ([]CheckRow, error) {
	rows, err := s.db.QueryContext(ctx, `
                SELECT id, kind, source, result, detail, comment, ran_at, actor, log
                FROM test_runs WHERE script_version_id = ? ORDER BY id DESC LIMIT 50`, versionID)
	if err != nil {
		return nil, fmt.Errorf("store: проверки версии %d: %w", versionID, err)
	}
	defer rows.Close()
	out := []CheckRow{}
	for rows.Next() {
		var c CheckRow
		if err := rows.Scan(&c.ID, &c.Kind, &c.Source, &c.Result, &c.Detail, &c.Comment, &c.RanAt, &c.Actor, &c.Log); err != nil {
			return nil, fmt.Errorf("store: проверки версии %d: строка: %w", versionID, err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// latestSignature — последняя подпись версии (действующая или нет:
// срок проверяет шлюз в момент выдачи).
func (s *Store) latestSignature(ctx context.Context, versionID int64) (SignatureRow, error) {
	var r SignatureRow
	err := s.db.QueryRowContext(ctx, `
                SELECT id, sha256, signed_by, signed_at, expires_at, signature
                FROM signatures WHERE script_version_id = ? ORDER BY id DESC LIMIT 1`, versionID).
		Scan(&r.ID, &r.SHA256, &r.SignedBy, &r.SignedAt, &r.ExpiresAt, &r.Signature)
	if errors.Is(err, sql.ErrNoRows) {
		return SignatureRow{}, ErrNotFound
	}
	if err != nil {
		return SignatureRow{}, fmt.Errorf("store: подпись версии %d: %w", versionID, err)
	}
	return r, nil
}

// validateScriptInput — имя, тип, категория: значения до базы.
func validateScriptInput(in CreateScriptInput) error {
	if in.Name == "" || len(in.Name) > MaxScriptNameLen {
		return fmt.Errorf("%w: имя пустое или длиннее %d", ErrScriptValue, MaxScriptNameLen)
	}
	if in.Kind != gate.KindCatalog && in.Kind != gate.KindScript {
		return fmt.Errorf("%w: тип %q", ErrScriptValue, in.Kind)
	}
	switch in.Category {
	case gate.CategoryGeneral, gate.CategoryDriver, gate.CategoryNic:
	default:
		return fmt.Errorf("%w: категория %q", ErrScriptValue, in.Category)
	}
	return nil
}

// shortSHA — короткий хэш для detail аудита (полный хэш не секрет,
// но журнал компактнее).
func shortSHA(sha string) string {
	if len(sha) > 16 {
		return sha[:16]
	}
	return sha
}
