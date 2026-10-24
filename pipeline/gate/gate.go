// Package gate — шлюз конвейера скриптов: единственное место, где
// решается, можно ли отправить задание агенту, и единственное место
// смены статусов конвейера.
//
// Конвейер статусов: draft → checked → tested → signed → pilot →
// released. Переходы только вперёд по цепочке и только через код
// этого пакета (store вызывает CanAdvance); обратный переход один —
// rejected. Диспетчеризация: CanDispatch отвергает задание, если
// не выполнено одновременно: статус не ниже tested, есть подпись
// владельца на этот хэш содержимого, срок подписи не истёк, цель
// в разрешённом наборе, для driver|nic пройден этап pilot. Всё, что
// исполняет команды на компьютерах, выключено по умолчанию: поля
// DispatchEnabled и AllowCustomScripts задаются конфигурацией
// сервера, в коде нет способа включить их неявно.
package gate

import (
	"errors"
	"fmt"
	"time"
)

// Статусы конвейера скрипта (версии скрипта).
const (
	StatusDraft    = "draft"
	StatusChecked  = "checked"
	StatusTested   = "tested"
	StatusSigned   = "signed"
	StatusPilot    = "pilot"
	StatusReleased = "released"
	StatusRejected = "rejected"
)

// Категории скриптов. Для driver|nic обязателен этап pilot на одном ПК.
const (
	CategoryGeneral = "general"
	CategoryDriver  = "driver"
	CategoryNic     = "nic"
)

// Типы заданий: проверенное действие каталога или произвольный скрипт.
const (
	KindCatalog = "catalog"
	KindScript  = "script"
)

// statusIndex — позиция статуса в цепочке; rejected вне цепочки (-1).
var statusIndex = map[string]int{
	StatusDraft:    0,
	StatusChecked:  1,
	StatusTested:   2,
	StatusSigned:   3,
	StatusPilot:    4,
	StatusReleased: 5,
	StatusRejected: -1,
}

// chain — порядок статусов вперёд; Next идёт по нему шаг за шагом.
var chain = []string{StatusDraft, StatusChecked, StatusTested, StatusSigned, StatusPilot, StatusReleased}

// IsStatus — строка является статусом конвейера.
func IsStatus(s string) bool {
	_, ok := statusIndex[s]
	return ok
}

// Index — позиция статуса в цепочке (rejected: -1, неизвестный: ошибка).
func Index(s string) (int, error) {
	i, ok := statusIndex[s]
	if !ok {
		return 0, fmt.Errorf("gate: неизвестный статус %q", s)
	}
	return i, nil
}

// Next — следующий статус цепочки; у released следующего нет.
func Next(from string) (string, error) {
	i, err := Index(from)
	if err != nil {
		return "", err
	}
	if i < 0 {
		return "", fmt.Errorf("gate: из %q переходов нет", from)
	}
	if i+1 >= len(chain) {
		return "", fmt.Errorf("gate: %q — конец цепочки", from)
	}
	return chain[i+1], nil
}

// CanAdvance — допустим ли переход from → to: вперёд ровно на один
// шаг цепочки или в rejected (единственный обратный; из rejected
// переходов нет). Подпись (tested → signed) проходит через эту же
// проверку: Sign-действие владельца — единственный вызывающий.
func CanAdvance(from, to string) error {
	if !IsStatus(from) || !IsStatus(to) {
		return fmt.Errorf("gate: переход %q → %q: неизвестный статус", from, to)
	}
	if from == StatusRejected {
		return fmt.Errorf("gate: %q — конечный статус, переходов нет", from)
	}
	if to == StatusRejected {
		return nil // единственный обратный переход
	}
	next, err := Next(from)
	if err != nil {
		return err
	}
	if to != next {
		return fmt.Errorf("gate: переход %q → %q вне цепочки: следующий только %q", from, to, next)
	}
	return nil
}

// AtLeast — статус не ниже минимального в цепочке (rejected — ниже всего).
func AtLeast(status, minimum string) bool {
	a, okA := statusIndex[status]
	b, okB := statusIndex[minimum]
	if !okA || !okB {
		return false
	}
	return a >= b
}

// Ошибки шлюза: вызывающий (агентский API) различает их, чтобы
// пометить цель expired (только просрочка подписи) или молча
// пропустить кандидата.
var (
	// ErrDispatchDisabled — диспетчеризация выключена (--enable-dispatch).
	ErrDispatchDisabled = errors.New("gate: диспетчеризация выключена на сервере")
	// ErrCustomScriptsDisabled — произвольные скрипты запрещены
	// (allow_custom_scripts выключен, задание kind=script).
	ErrCustomScriptsDisabled = errors.New("gate: произвольные скрипты запрещены на сервере")
	// ErrStatusTooLow — статус версии ниже tested (или rejected).
	ErrStatusTooLow = errors.New("gate: статус скрипта ниже «протестирован»")
	// ErrNotSigned — подписи владельца нет.
	ErrNotSigned = errors.New("gate: подписи владельца нет")
	// ErrContentChanged — содержимое изменено после подписи (хэш не тот).
	ErrContentChanged = errors.New("gate: скрипт изменён после подписи")
	// ErrSignatureExpired — срок подписи истёк.
	ErrSignatureExpired = errors.New("gate: срок подписи истёк")
	// ErrTargetNotAllowed — цель вне разрешённого набора задания.
	ErrTargetNotAllowed = errors.New("gate: цель вне разрешённого набора задания")
	// ErrPilotRequired — для driver|nic не пройден этап pilot на одном ПК.
	ErrPilotRequired = errors.New("gate: для драйверов и сетевых карт не пройден этап «один ПК»")
)

// Script — данные версии скрипта, которых достаточно шлюзу.
// SHA256 — хэш текущего содержимого (hex); SignedBy пуст — подписи
// нет; SignedSHA — хэш, покрытый подписью владельца.
type Script struct {
	Kind        string // catalog | script
	Category    string // general | driver | nic
	Status      string
	SHA256      string
	SignedBy    string
	SignedSHA   string
	SignExpires time.Time
	PilotPassed bool
}

// Job — задание и конфигурация сервера на момент отдачи. Target —
// цель, для которой спрашивают задание; Targets — разрешённый набор.
// IsPilot — задание этапа «один ПК»: для driver|nic это и есть
// пройденный пилот (после его успеха pilot_ok у версии).
type Job struct {
	DispatchEnabled    bool
	AllowCustomScripts bool
	Target             string
	Targets            []string
	IsPilot            bool
}

// CanDispatch — шлюз: задание попадает агенту только через эту
// проверку. Порядок проверок фиксирован: сначала переключатели
// сервера (политика), затем состояние скрипта, затем цель. now
// передаётся вызывающим — шлюз не читает часы сам (детерминизм
// тестов).
func CanDispatch(s Script, j Job, now time.Time) error {
	if !j.DispatchEnabled {
		return ErrDispatchDisabled
	}
	if s.Kind == KindScript && !j.AllowCustomScripts {
		return ErrCustomScriptsDisabled
	}
	if !AtLeast(s.Status, StatusTested) {
		return fmt.Errorf("%w: статус %q", ErrStatusTooLow, s.Status)
	}
	if s.SignedBy == "" {
		return ErrNotSigned
	}
	if s.SignedSHA != s.SHA256 {
		return fmt.Errorf("%w: подписан %s, содержимое %s", ErrContentChanged, short(s.SignedSHA), short(s.SHA256))
	}
	if !s.SignExpires.After(now) {
		return fmt.Errorf("%w: истёк %s", ErrSignatureExpired, s.SignExpires.UTC().Format(time.RFC3339))
	}
	if !contains(j.Targets, j.Target) {
		return fmt.Errorf("%w: %q", ErrTargetNotAllowed, j.Target)
	}
	if (s.Category == CategoryDriver || s.Category == CategoryNic) && !s.PilotPassed && !j.IsPilot {
		return ErrPilotRequired
	}
	return nil
}

// Quota — сколько целей суммарно может получить задание сейчас.
// Раскатка группами: группа 1 — один ПК; после его успеха — группа 2
// (10 % машин); после успеха всей группы 2 — остальные. doneCount —
// целей, отчитавшихся успехом; вызывающий сравнивает результат с
// числом уже выданных (delivered) и выдаёт не больше разницы.
func Quota(total, doneCount int) int {
	if total <= 0 {
		return 0
	}
	if doneCount < 1 {
		return 1 // группа 1: один ПК
	}
	tenPct := (total + 9) / 10 // ceil(total/10)
	if tenPct < 1 {
		tenPct = 1
	}
	q := total // группа 3: остальные
	if doneCount < 1+tenPct {
		q = 1 + tenPct // группа 2 открыта, но не завершена
	}
	if q > total {
		q = total
	}
	return q
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func short(hash string) string {
	if len(hash) > 12 {
		return hash[:12] + "…"
	}
	return hash
}
