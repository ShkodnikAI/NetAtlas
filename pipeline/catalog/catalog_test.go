package catalog

import (
	"strings"
	"testing"
)

// В каталоге минимум три шаблона из наряда, и каждый рендерится
// с умолчаниями без незаполненных маркеров.
func TestCatalogHasRequiredTemplates(t *testing.T) {
	all := All()
	if len(all) < 3 {
		t.Fatalf("шаблонов %d, минимум 3", len(all))
	}
	for _, tpl := range all {
		body, err := tpl.Render(map[string]string{})
		if err != nil {
			t.Fatalf("%s: рендер с умолчаниями: %v", tpl.Key, err)
		}
		if strings.Contains(body, "{{param:") {
			t.Fatalf("%s: остались незаполненные маркеры", tpl.Key)
		}
		if _, err := Get(tpl.Key); err != nil {
			t.Fatalf("%s: не находится по ключу: %v", tpl.Key, err)
		}
	}
	if _, err := Get("restart-spooler"); err != nil {
		t.Fatalf("нет шаблона перезапуска службы печати: %v", err)
	}
	if _, err := Get("clear-spooler"); err != nil {
		t.Fatalf("нет шаблона очистки очереди печати: %v", err)
	}
	if _, err := Get("net-report"); err != nil {
		t.Fatalf("нет шаблона диагностического отчёта: %v", err)
	}
}

// Значения подставляются в разрешённые места: явные параметры
// попадают в тело, умолчания — тоже.
func TestRenderSubstitutesValues(t *testing.T) {
	tpl, _ := Get("restart-spooler")
	body, err := tpl.Render(map[string]string{"service": "Spooler", "retries": "3"})
	if err != nil {
		t.Fatalf("валидный рендер: %v", err)
	}
	if !strings.Contains(body, "$service = 'Spooler'") {
		t.Fatal("service не подставлен")
	}
	if !strings.Contains(body, "$i -lt 3") {
		t.Fatal("retries не подставлен")
	}
	// Умолчания применяются, когда параметр не задан.
	body, err = tpl.Render(map[string]string{})
	if err != nil {
		t.Fatalf("рендер с умолчаниями: %v", err)
	}
	if !strings.Contains(body, "$service = 'Spooler'") || !strings.Contains(body, "$i -lt 2") {
		t.Fatal("умолчания не применились")
	}
}

// Параметры вне диапазона отвергаются.
func TestRenderRejectsOutOfRange(t *testing.T) {
	tpl, _ := Get("restart-spooler")
	if _, err := tpl.Render(map[string]string{"retries": "0"}); err == nil {
		t.Fatal("retries=0 (ниже минимума) не отвергнут")
	}
	if _, err := tpl.Render(map[string]string{"retries": "6"}); err == nil {
		t.Fatal("retries=6 (выше максимума) не отвергнут")
	}
	tpl, _ = Get("net-report")
	if _, err := tpl.Render(map[string]string{"top_routes": "99"}); err == nil {
		t.Fatal("top_routes=99 не отвергнут")
	}
}

// Параметры с лишними символами отвергаются белой маской.
func TestRenderRejectsBadCharacters(t *testing.T) {
	tpl, _ := Get("restart-spooler")
	for _, bad := range []string{"a'; Remove-Item C:\\ -Force; '", "svc`;calc", "имя с кириллицей", "tab\tname", "quote\""} {
		if _, err := tpl.Render(map[string]string{"service": bad}); err == nil {
			t.Fatalf("service %q не отвергнут", bad)
		}
	}
	// Инъекция через числовой параметр: не целое число.
	if _, err := tpl.Render(map[string]string{"retries": "2; calc"}); err == nil {
		t.Fatal("retries с командой не отвергнут")
	}
}

// Неизвестные параметры отвергаются — мимо схемы в скрипт не попасть.
func TestRenderRejectsUnknownParams(t *testing.T) {
	tpl, _ := Get("clear-spooler")
	if _, err := tpl.Render(map[string]string{"evil": "x"}); err == nil {
		t.Fatal("неизвестный параметр не отвергнут")
	}
}

// Required-параметр без значения — ошибка.
func TestRequiredParam(t *testing.T) {
	tpl := Template{
		Key: "t", Title: "t", Params: []Param{{Key: "must", Title: "m", Type: "string", Required: true, Pattern: `^[a-z]+$`}},
		Body: "x {{param:must}}",
	}
	if _, err := tpl.Render(map[string]string{}); err == nil {
		t.Fatal("обязательный параметр без значения не отвергнут")
	}
	if _, err := tpl.Render(map[string]string{"must": "abc"}); err != nil {
		t.Fatalf("обязательный параметр со значением: %v", err)
	}
}

// Только-чтение помечено у диагностического отчёта.
func TestNetReportIsReadOnly(t *testing.T) {
	tpl, _ := Get("net-report")
	if !tpl.ReadOnly {
		t.Fatal("net-report должен быть только-чтение")
	}
}
