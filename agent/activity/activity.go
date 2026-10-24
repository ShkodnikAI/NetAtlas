// Package activity — сбор минимальных сведений о работе за
// компьютером (NR-012). Инвариант из docs/DECISIONS.md: собираются
// активное приложение (только имя процесса), домены сайтов
// (только host, из DNS-кэша клиента), время активности и простоя.
// НЕ собирается и в этом пакете отсутствует: нажатия клавиш,
// содержимое переписки, пароли, полные адреса страниц, скриншоты.
// Сбор по умолчанию выключен (локальный флаг владельца) и
// включается только для рабочих компьютеров.
package activity

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// SchemaVersion — версия схемы отчёта (жёсткий белый список полей).
const SchemaVersion = 1

// Границы сбора.
const (
	// SnapshotInterval — период мгновенного снимка активного окна.
	SnapshotInterval = 15 * time.Second
	// DNSInterval — период опроса DNS-кэша.
	DNSInterval = time.Minute
	// WindowLength — длина агрегируемого окна.
	WindowLength = 5 * time.Minute
	// MaxAppNames — предел числа приложений в агрегате.
	MaxAppNames = 100
	// MaxDomains — предел числа доменов в агрегате.
	MaxDomains = 200
	// MaxDomainLen — предел длины имени домена.
	MaxDomainLen = 253
	// MaxAccountLen — предел длины учётной записи.
	MaxAccountLen = 128
)

// Report — 5-минутный агрегат. Жёсткий белый список полей: любые
// другие поля в JSON отвергаются сервером (DisallowUnknownFields),
// тест отражением проверяет, что структура не расширилась.
type Report struct {
	SchemaVer   int            `json:"schema_ver"`
	WindowStart string         `json:"window_start"` // начало окна, UTC
	Account     string         `json:"account"`      // учётная запись сотрудника
	ActiveSec   int            `json:"active_sec"`
	IdleSec     int            `json:"idle_sec"`
	Apps        map[string]int `json:"apps"`    // приложение → секунды
	Domains     map[string]int `json:"domains"` // домен → число запросов
}

// hostRe — допустимые символы имени домена: буквы/цифры/дефис/точка.
var hostRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$`)

// ExtractHost — из строки источника только имя домена: схема, путь,
// параметры, порт, учётные данные отбрасываются. Строка без схемы
// считается доменом, если проходит белую маску; иначе — пусто.
// Это единственный фильтр доменов: содержимое страниц недоступно
// по построению (источник — DNS-кэш, там только имена).
func ExtractHost(raw string) string {
	s := strings.TrimSpace(strings.ToLower(raw))
	if s == "" {
		return ""
	}
	// Вырезать схему: url.Parse с фиктивной схемой отдаёт Hostname()
	// без порта, пути, параметров и учётных данных.
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if u, err := url.Parse("scheme://" + s); err == nil && u.Hostname() != "" {
		s = u.Hostname()
	}
	if len(s) == 0 || len(s) > MaxDomainLen || !hostRe.MatchString(s) {
		return ""
	}
	return s
}

// Snapshot — мгновенное состояние машины: имя процесса активного
// окна (без заголовка), миллисекунды простоя, домены из DNS-кэша.
// Запрещённых полей в снимке нет по построению.
type Snapshot struct {
	Process string   // имя exe активного окна
	IdleMS  int64    // миллисекунд без ввода
	Domains []string // имена доменов из DNS-кэша
}

// AccountInfo — учётная запись и члены группы администраторов
// (исключения по умолчанию).
type AccountInfo struct {
	Account string   `json:"account"`
	IsAdmin bool     `json:"is_admin"`
	Admins  []string `json:"admins"`
}

// Policy — локальная политика сбора: включение и исключения.
type Policy struct {
	Enabled bool
	// ExcludeAccounts — учётные записи, по которым не собираем.
	// По умолчанию: все члены группы администраторов и владелец.
	ExcludeAccounts []string
}

// Allowed — сбор разрешён учётной записи? Исключённые (админы,
// владелец) не собираются (сравнение без учёта регистра, доменная
// часть отбрасывается).
func (p Policy) Allowed(account string) bool {
	if account == "" {
		return false
	}
	local := localAccount(account)
	for _, ex := range p.ExcludeAccounts {
		if strings.EqualFold(localAccount(ex), local) {
			return false
		}
	}
	return true
}

// localAccount — имя без доменной части (DOMAIN\user → user).
func localAccount(a string) string {
	if i := strings.LastIndexByte(a, '\\'); i >= 0 {
		return a[i+1:]
	}
	return a
}

// Collector — агрегатор: мгновенные снимки складываются в 5-минутное
// окно, готовое окно забирает основной цикл агента. Потокобезопасен:
// снимки делает отдельная горутина.
type Collector struct {
	mu       sync.Mutex
	account  string
	appSec   map[string]int
	domainN  map[string]int
	activeMS int64
	idleMS   int64
	windowAt time.Time
}

// NewCollector — агрегатор с учётной записью сотрудника.
func NewCollector(account string) *Collector {
	return &Collector{account: account, appSec: map[string]int{}, domainN: map[string]int{}}
}

// AddSnapshot — мгновенный снимок: имя процесса (только имя), просто
// в миллисекундах, дельта доменов. Заголовков окон в снимке нет:
// поле отсутствует по построению (инвариант наряда).
func (c *Collector) AddSnapshot(process string, idleMS int64, domains []string, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.windowAt.IsZero() {
		c.windowAt = now.Truncate(WindowLength)
	}
	if idleMS > 60_000 {
		// Долгое отсутствие ввода — простой: ни активности, ни
		// приложения, ни доменов в это окно не добавляется.
		c.idleMS += SnapshotInterval.Milliseconds()
		return
	}
	c.activeMS += SnapshotInterval.Milliseconds()
	if p := sanitizeProcess(process); p != "" {
		c.appSec[p] += int(SnapshotInterval.Seconds())
	}
	for _, d := range domains {
		if host := ExtractHost(d); host != "" {
			c.domainN[host]++
		}
	}
}

// TakeReport — готовое окно (nil — окно ещё не заполнено). Окно
// сбрасывается: следующий агрегат начинается заново.
func (c *Collector) TakeReport(now time.Time) *Report {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.windowAt.IsZero() || now.Sub(c.windowAt) < WindowLength {
		return nil
	}
	rep := &Report{
		SchemaVer:   SchemaVersion,
		WindowStart: c.windowAt.UTC().Format(time.RFC3339),
		Account:     c.account,
		Apps:        limitMap(c.appSec, MaxAppNames),
		Domains:     limitMap(c.domainN, MaxDomains),
		ActiveSec:   int(c.activeMS / 1000),
		IdleSec:     int(c.idleMS / 1000),
	}
	c.appSec = map[string]int{}
	c.domainN = map[string]int{}
	c.activeMS, c.idleMS = 0, 0
	c.windowAt = now.Truncate(WindowLength)
	return rep
}

// Validate — самопроверка отчёта перед отправкой: границы и маски.
func (r *Report) Validate() error {
	if r.SchemaVer != SchemaVersion {
		return fmt.Errorf("activity: версия схемы %d", r.SchemaVer)
	}
	if len(r.Account) == 0 || len(r.Account) > MaxAccountLen {
		return errors.New("activity: учётная запись отсутствует или длиннее лимита")
	}
	if len(r.Apps) > MaxAppNames || len(r.Domains) > MaxDomains {
		return errors.New("activity: слишком много имён в агрегате")
	}
	if _, err := time.Parse(time.RFC3339, r.WindowStart); err != nil {
		return errors.New("activity: окно без времени")
	}
	for a := range r.Apps {
		if sanitizeProcess(a) != a {
			return errors.New("activity: имя приложения не нормализовано (путь или лишние символы)")
		}
	}
	for d := range r.Domains {
		if ExtractHost(d) != d {
			return errors.New("activity: домен вне маски")
		}
	}
	return nil
}

// sanitizeProcess — имя процесса: только буквы/цифры/точка/дефис/
// подчёркивание/пробел, без путей и кавычек. Заголовки окон сюда не
// попадают никогда: снимок их не читает.
func sanitizeProcess(name string) string {
	name = strings.TrimSpace(name)
	if i := strings.LastIndexAny(name, `\/`); i >= 0 {
		name = name[i+1:]
	}
	if len(name) == 0 || len(name) > 64 {
		return ""
	}
	for _, r := range name {
		ok := r == ' ' || r == '.' || r == '-' || r == '_' ||
			(r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			r >= 0x80 // локализованные имена процессов
		if !ok {
			return ""
		}
	}
	return name
}

// limitMap — обрезка карты по пределу с детерминированным выбором.
func limitMap(m map[string]int, limit int) map[string]int {
	if len(m) <= limit {
		return m
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make(map[string]int, limit)
	for _, k := range keys[:limit] {
		out[k] = m[k]
	}
	return out
}
