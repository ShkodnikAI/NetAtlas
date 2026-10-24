// Тесты сборщиков на фикстурах (реальная по форме выдача
// PowerShell, включая русскую локаль), сборка отчёта, устойчивость
// к ошибкам сборщиков.
package collect

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixture(t *testing.T, name string) json.RawMessage {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("фикстура %s: %v", name, err)
	}
	return json.RawMessage(raw)
}

// fakeRunner — подставной раннер: сценарий → фикстура или ошибка.
type fakeRunner struct {
	fail map[string]error
}

func (f *fakeRunner) Run(_ context.Context, script string) (json.RawMessage, error) {
	if err := f.fail[script]; err != nil {
		return nil, err
	}
	return fixture(&testing.T{}, script+"_ru.json"), nil
}

// Парсер ОС: русская локаль, два обновления, последнее — по дате.
func TestParseOSInfoRuLocale(t *testing.T) {
	v, err := parseOSInfo(fixture(t, "osinfo_ru.json"))
	if err != nil {
		t.Fatalf("parseOSInfo: %v", err)
	}
	osi := v.(*OSInfo)
	if osi.Caption != "Microsoft Windows 11 Pro" || osi.Architecture != "64-разрядная" {
		t.Fatalf("поля ОС: %+v", osi)
	}
	if len(osi.Hotfixes) != 2 || osi.Hotfixes[1].ID != "KB5045033" {
		t.Fatalf("обновления: %+v", osi.Hotfixes)
	}
	if osi.LatestHotfix != "12.10.2026 0:00:00" {
		t.Fatalf("последнее обновление: %q", osi.LatestHotfix)
	}
}

// ОС без обновлений: пустой список, не ошибка.
func TestParseOSInfoNoHotfix(t *testing.T) {
	v, err := parseOSInfo(fixture(t, "osinfo_nohotfix.json"))
	if err != nil {
		t.Fatalf("parseOSInfo: %v", err)
	}
	osi := v.(*OSInfo)
	if len(osi.Hotfixes) != 0 || osi.LatestHotfix != "" {
		t.Fatalf("без обновлений: %+v", osi)
	}
}

// Железо: CPU, слоты ОЗУ, плата, BIOS с нормализованной CIM-датой.
func TestParseHardwareRuLocale(t *testing.T) {
	v, err := parseHardware(fixture(t, "hardware_ru.json"))
	if err != nil {
		t.Fatalf("parseHardware: %v", err)
	}
	hw := v.(*Hardware)
	if hw.TotalPhysicalMemory != "17179869184" {
		t.Fatalf("ОЗУ: %q", hw.TotalPhysicalMemory)
	}
	if len(hw.CPUs) != 1 || hw.CPUs[0].Cores != 6 || hw.CPUs[0].Logical != 12 || hw.CPUs[0].MaxClockMHz != 2904 {
		t.Fatalf("CPU: %+v", hw.CPUs)
	}
	if len(hw.MemoryModules) != 2 || hw.MemoryModules[1].Manufacturer != "" {
		t.Fatalf("модули ОЗУ: %+v", hw.MemoryModules)
	}
	if hw.BaseBoard == nil || hw.BaseBoard.Product != "PRIME H410M-E" {
		t.Fatalf("плата: %+v", hw.BaseBoard)
	}
	if hw.BIOS == nil || hw.BIOS.ReleaseDate != "2021-03-12" {
		t.Fatalf("BIOS: %+v", hw.BIOS)
	}
}

// Диски: у SSD износ и температура заполнены, у HDD поля отсутствуют
// (nil), а не нули.
func TestParseDisksSSDCounters(t *testing.T) {
	v, err := parseDisks(fixture(t, "disks_ru.json"))
	if err != nil {
		t.Fatalf("parseDisks: %v", err)
	}
	d := v.(*Disks)
	if len(d.Disks) != 2 || len(d.Volumes) != 2 {
		t.Fatalf("состав: %+v", d)
	}
	ssd := d.Disks[0]
	if ssd.Wear == nil || *ssd.Wear != 5 || ssd.Temperature == nil || *ssd.Temperature != 34 {
		t.Fatalf("счётчики SSD: %+v", ssd)
	}
	hdd := d.Disks[1]
	if hdd.Wear != nil || hdd.Temperature != nil {
		t.Fatalf("у HDD счётчики должны отсутствовать: %+v", hdd)
	}
	if d.Volumes[0].Label != "Система" || d.Volumes[1].SizeRemaining != "512414220288" {
		t.Fatalf("тома: %+v", d.Volumes)
	}
}

// Счётчики недоступны вообще: поля отсутствуют, разбор проходит.
func TestParseDisksNoCounters(t *testing.T) {
	v, err := parseDisks(fixture(t, "disks_no_counters.json"))
	if err != nil {
		t.Fatalf("parseDisks: %v", err)
	}
	d := v.(*Disks)
	if d.Disks[0].Wear != nil || d.Disks[0].Temperature != nil {
		t.Fatalf("недоступные счётчики должны отсутствовать: %+v", d.Disks[0])
	}
	if d.Volumes[0].Label != "" || d.Volumes[0].SizeRemaining != "0" {
		t.Fatalf("тома: %+v", d.Volumes)
	}
}

// Сеть: массивы IPv4, пустая скорость у отключённого адаптера.
func TestParseNetworkRuLocale(t *testing.T) {
	v, err := parseNetwork(fixture(t, "network_ru.json"))
	if err != nil {
		t.Fatalf("parseNetwork: %v", err)
	}
	ad := v.([]NetAdapter)
	if len(ad) != 3 {
		t.Fatalf("адаптеров %d, хочу 3", len(ad))
	}
	if ad[0].LinkSpeed != "1 Гбит/с" || len(ad[0].IPv4) != 2 || ad[0].IPv4[0] != "192.168.1.10" {
		t.Fatalf("Ethernet: %+v", ad[0])
	}
	if ad[1].Status != "Disconnected" || len(ad[1].IPv4) != 0 {
		t.Fatalf("Wi-Fi: %+v", ad[1])
	}
}

// Драйверы: CIM-даты нормализованы, запись без имени устройства
// отброшена.
func TestParseDriversRuLocale(t *testing.T) {
	v, err := parseDrivers(fixture(t, "drivers_ru.json"))
	if err != nil {
		t.Fatalf("parseDrivers: %v", err)
	}
	dr := v.([]Driver)
	if len(dr) != 3 {
		t.Fatalf("драйверов %d, хочу 3 (без пустого имени)", len(dr))
	}
	if dr[0].Date != "2024-03-01" {
		t.Fatalf("CIM-дата: %q", dr[0].Date)
	}
	if dr[1].Manufacturer != "" {
		t.Fatalf("пустой производитель должен сохраниться пустым: %+v", dr[1])
	}
}

// Программы: без DisplayName отброшены, повторы сохраняются (это
// факт машины), пустой издатель — пустая строка.
func TestParsePrograms(t *testing.T) {
	v, err := parsePrograms(fixture(t, "programs_ru.json"))
	if err != nil {
		t.Fatalf("parsePrograms: %v", err)
	}
	pr := v.([]Program)
	if len(pr) != 4 {
		t.Fatalf("программ %d, хочу 4 (без записи без имени)", len(pr))
	}
	if pr[1].Publisher != "" || pr[1].Name != "7-Zip 24.09 (x64)" {
		t.Fatalf("7-Zip: %+v", pr[1])
	}
}

// Сборка отчёта: версия схемы, ошибки сборщиков не роняют отчёт.
func TestBuildReportToleratesErrors(t *testing.T) {
	runner := &fakeRunner{fail: map[string]error{
		"disks":   errors.New("powershell: disks: выход 1"),
		"drivers": errors.New("collect: powershell drivers: пустой вывод"),
	}}
	cs := DefaultCollectors(runner)
	rep := BuildReport(context.Background(), "pc-1", cs, time.Date(2026, 10, 24, 10, 0, 0, 0, time.UTC))
	if rep.InventorySchemaVersion != SchemaVersion || SchemaVersion != 1 {
		t.Fatalf("версия схемы: %d", rep.InventorySchemaVersion)
	}
	if rep.Hostname != "pc-1" || rep.CollectedAt == "" {
		t.Fatalf("шапка отчёта: %+v", rep)
	}
	if len(rep.CollectorErrors) != 2 {
		t.Fatalf("collector_errors: %v", rep.CollectorErrors)
	}
	if rep.Disks != nil || rep.Drivers != nil {
		t.Fatal("упавшие сборщики не должны заполнять поля")
	}
	if rep.OS == nil || rep.OS.Caption != "Microsoft Windows 11 Pro" {
		t.Fatalf("успешный сборщик заполнил поле: %+v", rep.OS)
	}
	// Отчёт сериализуется: тело отправления.
	if raw, err := json.Marshal(rep); err != nil || len(raw) == 0 {
		t.Fatalf("marshal отчёта: %v", err)
	}
}

// Имя сценария не может уйти за пределы каталога scripts.
func TestPowerShellRunnerRejectsBadScriptName(t *testing.T) {
	r := &PowerShellRunner{Exe: "нет-такого-бинаря"} // имя проверяется раньше запуска
	if _, err := r.Run(context.Background(), "../secrets"); err == nil ||
		!strings.Contains(err.Error(), "недопустимое имя сценария") {
		t.Fatalf("имя с путём: %v, хочу отказ проверки имени", err)
	}
}
