// Тесты сбора активности (NR-012): фильтр доменов оставляет только
// host, учётные записи администраторов исключены, агрегация окон,
// белый список полей отчёта (url, title, keys, screenshot отсутствуют).
package activity

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Фильтр домена: схемы, пути, параметры, порты и пароли в URL
// отбрасываются — остаётся только host.
func TestExtractHost(t *testing.T) {
	cases := []struct{ in, want string }{
		{"https://u:p@h/x?q=1", "h"}, // наряд: пароль в URL
		{"http://example.com/path/page.html", "example.com"},
		{"https://mail.example.org:8443/inbox?x=1#frag", "mail.example.org"},
		{"example.com", "example.com"},
		{"  EXAMPLE.COM  ", "example.com"},
		{"ftp://files.example.net/pub", "files.example.net"},
		{"https://user:secret@10.0.0.5:8080/admin", "10.0.0.5"},
		{"", ""},
		{"   ", ""},
		{"javascript:alert(1)", ""},
		{"in-domain with space.com", ""},
		{strings.Repeat("a", 260) + ".com", ""},
		{"https://", ""},
		{"bad|pipe.com", ""},
		{"header injection\r\nset-cookie: x", ""},
	}
	for _, c := range cases {
		if got := ExtractHost(c.in); got != c.want {
			t.Errorf("ExtractHost(%q) = %q, хочу %q", c.in, got, c.want)
		}
	}
}

// Учётная запись администратора не собирается: исключения по имени
// без учёта регистра и доменной части.
func TestPolicyExcludesAdmins(t *testing.T) {
	p := Policy{Enabled: true, ExcludeAccounts: []string{"ADMIN-PC\\Админ", "DOMAIN\\boss"}}
	if p.Allowed("Админ") {
		t.Fatal("администратор собирается")
	}
	if p.Allowed("ADMIN-PC\\админ") {
		t.Fatal("администратор (регистр) собирается")
	}
	if p.Allowed("boss") {
		t.Fatal("владелец собирается")
	}
	if !p.Allowed("DOMAIN\\сотрудник") {
		t.Fatal("обычный сотрудник не собирается, хотя не в исключениях")
	}
	if p.Allowed("") {
		t.Fatal("пустая учётная запись собирается")
	}
	p2 := Policy{Enabled: true} // исключений нет: обычные собираются
	if !p2.Allowed("сотрудник") {
		t.Fatal("сотрудник не собирается без исключений")
	}
}

// Агрегация: окно 5 минут, приложения в секундах, домены — счётчик,
// простой больше минуты уходит в idle.
func TestCollectorAggregates(t *testing.T) {
	c := NewCollector("DOMAIN\\иванов")
	base := time.Date(2026, 10, 25, 10, 0, 0, 0, time.UTC)
	// 4 снимка по 15 с с активным вводом.
	for i := 0; i < 4; i++ {
		c.AddSnapshot("chrome.exe", 0, []string{"https://example.com/page", "example.org"}, base.Add(time.Duration(i)*SnapshotInterval))
	}
	// Снимок с простоем: отсутствие ввода больше минуты.
	c.AddSnapshot("chrome.exe", 90_000, nil, base.Add(4*SnapshotInterval))
	// Окно ещё не заполнено.
	if rep := c.TakeReport(base.Add(4 * SnapshotInterval)); rep != nil {
		t.Fatalf("окно отдалось раньше времени: %+v", rep)
	}
	rep := c.TakeReport(base.Add(WindowLength))
	if rep == nil {
		t.Fatal("готовое окно не отдалось")
	}
	if err := rep.Validate(); err != nil {
		t.Fatalf("отчёт не валиден: %v", err)
	}
	if rep.Apps["chrome.exe"] != 4*15 { // снимок с простоем не попал в приложения
		t.Fatalf("секунды приложения: %d", rep.Apps["chrome.exe"])
	}
	if rep.Domains["example.com"] != 4 || rep.Domains["example.org"] != 4 {
		t.Fatalf("счётчики доменов: %+v", rep.Domains)
	}
	if rep.ActiveSec != 60 || rep.IdleSec != 15 {
		t.Fatalf("активность/простой: %d/%d", rep.ActiveSec, rep.IdleSec)
	}
	if rep.Account != "DOMAIN\\иванов" || rep.SchemaVer != SchemaVersion {
		t.Fatalf("поля отчёта: %+v", rep)
	}
	// После забора счётчики сброшены.
	if rep2 := c.TakeReport(base.Add(WindowLength + SnapshotInterval)); rep2 != nil {
		t.Fatalf("второе окно отдалось сразу: %+v", rep2)
	}
}

// Белый список полей отчёта: структура не содержит и не может
// содержать запрещённых полей (url, title, keys, screenshot…).
// Тест падает, если добавить поле вне списка.
func TestReportFieldWhitelist(t *testing.T) {
	typ := reflect.TypeOf(Report{})
	allowed := map[string]bool{
		"schema_ver": true, "window_start": true, "account": true,
		"active_sec": true, "idle_sec": true, "apps": true, "domains": true,
	}
	var got []string
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		tag := f.Tag.Get("json")
		name := strings.Split(tag, ",")[0]
		if name == "" {
			name = f.Name
		}
		got = append(got, name)
		if !allowed[name] {
			t.Errorf("поле %q вне белого списка отчёта", name)
		}
	}
	if len(got) != len(allowed) {
		t.Errorf("полей %d, в белом списке %d: %v", len(got), len(allowed), got)
	}
	// Запрещённые имена не встречаются даже частично.
	for _, f := range got {
		for _, banned := range []string{"url", "title", "key", "screenshot", "clipboard", "password", "hook"} {
			if strings.Contains(strings.ToLower(f), banned) {
				t.Errorf("поле %q содержит запрещённый корень %q", f, banned)
			}
		}
	}
}

// Валидация отчёта: маски имён приложений и доменов.
func TestReportValidate(t *testing.T) {
	rep := &Report{
		SchemaVer: SchemaVersion, WindowStart: time.Now().UTC().Format(time.RFC3339),
		Account: "user", Apps: map[string]int{"notepad.exe": 10}, Domains: map[string]int{"example.com": 2},
	}
	if err := rep.Validate(); err != nil {
		t.Fatalf("валидный отчёт: %v", err)
	}
	// Путь в имени приложения — отказ.
	bad := *rep
	bad.Apps = map[string]int{"C:\\evil\\x.exe": 10}
	if err := bad.Validate(); err == nil {
		t.Fatal("путь в имени приложения прошёл")
	}
	// Домен с путём — отказ (фильтр не применён).
	bad = *rep
	bad.Domains = map[string]int{"example.com/steal": 1}
	if err := bad.Validate(); err == nil {
		t.Fatal("домен с путём прошёл")
	}
	// Чужая версия схемы — отказ.
	bad = *rep
	bad.SchemaVer = 2
	if err := bad.Validate(); err == nil {
		t.Fatal("версия схемы не проверяется")
	}
	// Слишком много имён (валидных!) — отказ: только лимит может
	// сработать, нормализация тут не при чём.
	bad = *rep
	bad.Apps = map[string]int{}
	for i := 0; i < MaxAppNames+1; i++ {
		bad.Apps[fmt.Sprintf("app%05d.exe", i)] = 1
	}
	if err := bad.Validate(); err == nil {
		t.Fatal("предел приложений не работает")
	}
	bad.Domains = map[string]int{}
	for i := 0; i < MaxDomains+1; i++ {
		bad.Domains[fmt.Sprintf("site%05d.example.com", i)] = 1
	}
	if err := bad.Validate(); err == nil {
		t.Fatal("предел доменов не работает")
	}
}

// Заголовок окна не читается по построению: в пакете нет функций
// GetWindowText* на активном окне (только имя процесса).
func TestNoWindowTitleSource(t *testing.T) {
	src := packageSource(t, ".")
	for _, banned := range []string{"GetWindowText", "WM_GETTEXT", "GetWindowLong"} {
		if strings.Contains(src, banned) {
			t.Errorf("в пакете есть %s: чтение заголовков запрещено инвариантом", banned)
		}
	}
}
