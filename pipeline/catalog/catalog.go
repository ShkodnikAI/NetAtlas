// Package catalog — каталог проверенных действий: шаблоны скриптов
// с параметрами. Параметры валидируются по схеме (тип, диапазон,
// белая маска символов), шаблон подставляет значения только в
// разрешённые места — маркеры {{param:имя}}. Произвольная
// конкатенация строк в команду исключена: значение, не прошедшее
// схему, не попадает в скрипт никогда.
package catalog

import (
	"fmt"
	"regexp"
	"strings"
)

// Param — схема одного параметра шаблона.
type Param struct {
	Key      string `json:"key"`               // имя в маркере и в запросе
	Title    string `json:"title"`             // человекочитаемое имя
	Type     string `json:"type"`              // string | int
	Default  string `json:"default"`           // значение по умолчанию
	Required bool   `json:"required"`          // без значения — ошибка
	Pattern  string `json:"pattern,omitempty"` // string: белая маска символов
	Min      *int64 `json:"min,omitempty"`     // int: нижняя граница
	Max      *int64 `json:"max,omitempty"`     // int: верхняя граница
}

// Template — проверенное действие каталога.
type Template struct {
	Key         string  `json:"key"`
	Title       string  `json:"title"`
	Description string  `json:"description"`
	ReadOnly    bool    `json:"read_only"` // только читает данные
	Params      []Param `json:"params"`
	Body        string  `json:"-"` // PowerShell с маркерами {{param:key}}
}

// paramRe — маркер подстановки в теле шаблона.
var paramRe = regexp.MustCompile(`\{\{param:([a-z_]+)\}\}`)

// intRe — целое число без знака (знак не нужен проверенным действиям).
var intRe = regexp.MustCompile(`^[0-9]{1,9}$`)

// Validate — значения параметров по схеме: неизвестные отвергаются,
// отсутствующие required — ошибка, у int — формат и диапазон, у
// string — белая маска символов. Возвращает нормализованные значения
// (подставленные умолчания).
func (t Template) Validate(params map[string]string) (map[string]string, error) {
	out := make(map[string]string, len(t.Params))
	schema := make(map[string]Param, len(t.Params))
	for _, p := range t.Params {
		schema[p.Key] = p
		if v, ok := params[p.Key]; ok && v != "" {
			out[p.Key] = v
		} else if p.Required {
			return nil, fmt.Errorf("catalog: параметр %q обязателен", p.Key)
		} else {
			out[p.Key] = p.Default
		}
	}
	// Лишние ключи отвергаются: у параметра нет шанса попасть в скрипт мимо схемы.
	for k := range params {
		if _, ok := schema[k]; !ok {
			return nil, fmt.Errorf("catalog: неизвестный параметр %q", k)
		}
	}
	for _, p := range t.Params {
		v := out[p.Key]
		switch p.Type {
		case "int":
			if !intRe.MatchString(v) {
				return nil, fmt.Errorf("catalog: параметр %q: нужно целое число", p.Key)
			}
			var n int64
			for _, r := range v {
				n = n*10 + int64(r-'0')
			}
			if (p.Min != nil && n < *p.Min) || (p.Max != nil && n > *p.Max) {
				var lo, hi int64
				if p.Min != nil {
					lo = *p.Min
				}
				if p.Max != nil {
					hi = *p.Max
				}
				return nil, fmt.Errorf("catalog: параметр %q: вне диапазона %d..%d", p.Key, lo, hi)
			}
		default: // string
			if p.Pattern != "" && !regexp.MustCompile(p.Pattern).MatchString(v) {
				return nil, fmt.Errorf("catalog: параметр %q: недопустимые символы", p.Key)
			}
		}
	}
	return out, nil
}

// Render — валидация параметров и подстановка только в маркеры
// {{param:key}}. Маркер без схемы — ошибка сборки шаблона (ловится
// тестами каталога), а не молчаливая подстановка.
func (t Template) Render(params map[string]string) (string, error) {
	values, err := t.Validate(params)
	if err != nil {
		return "", err
	}
	keys := make(map[string]string, len(t.Params))
	for _, p := range t.Params {
		keys[p.Key] = values[p.Key]
	}
	body := paramRe.ReplaceAllStringFunc(t.Body, func(m string) string {
		key := paramRe.FindStringSubmatch(m)[1]
		if v, ok := keys[key]; ok {
			return v
		}
		return m // маркер без параметра в схеме останется видимым: тесты каталога его ловят
	})
	if strings.Contains(body, "{{param:") {
		return "", fmt.Errorf("catalog: шаблон %q: незаполненный маркер", t.Key)
	}
	return body, nil
}

// Get — шаблон по ключу; неизвестный ключ — ошибка.
func Get(key string) (Template, error) {
	for _, t := range All() {
		if t.Key == key {
			return t, nil
		}
	}
	return Template{}, fmt.Errorf("catalog: нет шаблона %q", key)
}

// All — все шаблоны каталога. Минимум наряда: перезапуск службы
// печати, очистка очереди печати, диагностический отчёт сети
// (только чтение).
func All() []Template {
	retriesMin, retriesMax := int64(1), int64(5)
	routesMin, routesMax := int64(1), int64(20)
	return []Template{
		{
			Key:         "restart-spooler",
			Title:       "Перезапустить службу печати",
			Description: "Останавливает и запускает службу печати Windows (Restart-Service). Действие меняет состояние службы, данные очереди не трогает.",
			ReadOnly:    false,
			Params: []Param{
				{
					Key:     "service",
					Title:   "Имя службы",
					Type:    "string",
					Default: "Spooler",
					Pattern: `^[A-Za-z][A-Za-z0-9 ._-]{0,63}$`,
				},
				{Key: "retries", Title: "Число попыток запуска", Type: "int", Default: "2", Min: &retriesMin, Max: &retriesMax},
			},
			Body: `# Проверенное действие: перезапуск службы печати.
$ErrorActionPreference = 'Stop'
$service = '{{param:service}}'
$ok = $false
for ($i = 0; $i -lt {{param:retries}}; $i++) {
    Restart-Service -Name $service -Force
    Start-Sleep -Seconds 3
    if ((Get-Service -Name $service).Status -eq 'Running') { $ok = $true; break }
}
if (-not $ok) { throw "Служба $service не перешла в состояние Running" }
"OK: служба $service перезапущена"
`,
		},
		{
			Key:         "clear-spooler",
			Title:       "Очистить очередь печати",
			Description: "Останавливает службу печати, удаляет файлы очереди и запускает службу заново. Драйверы принтеров не трогаются.",
			ReadOnly:    false,
			Params:      []Param{},
			Body: `# Проверенное действие: очистка очереди печати.
$ErrorActionPreference = 'Stop'
Stop-Service -Name Spooler -Force
Remove-Item -Path 'C:\Windows\System32\spool\PRINTERS\*' -Force -ErrorAction SilentlyContinue
Start-Service -Name Spooler
"OK: очередь печати очищена"
`,
		},
		{
			Key:         "net-report",
			Title:       "Собрать диагностический отчёт сети (только чтение)",
			Description: "Собирает конфигурацию адаптеров, маршруты, ARP-таблицу и статистику. Ничего не меняет: только чтение состояния.",
			ReadOnly:    true,
			Params: []Param{
				{Key: "top_routes", Title: "Сколько строк маршрутов вывести", Type: "int", Default: "10", Min: &routesMin, Max: &routesMax},
			},
			Body: `# Проверенное действие: диагностический отчёт сети (только чтение).
$lines = @()
$lines += '=== ipconfig /all ==='
$lines += (ipconfig /all | Out-String)
$lines += '=== Get-NetAdapter ==='
$lines += (Get-NetAdapter | Select-Object Name, InterfaceDescription, Status, LinkSpeed | Format-Table -AutoSize | Out-String)
$lines += '=== Get-NetIPConfiguration ==='
$lines += (Get-NetIPConfiguration | Format-List | Out-String)
$lines += '=== route print (первые {{param:top_routes}} строк) ==='
$lines += ((route print | Out-String) -split "` + "`n`" + `" | Select-Object -First {{param:top_routes}})
$lines += '=== arp -a ==='
$lines += (arp -a | Out-String)
$lines -join "` + "`n`" + `"
`,
		},
	}
}
