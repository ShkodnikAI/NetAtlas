// Тесты движка правил (NR-009): пороги на границах, таблицы сроков,
// загрузчик, переопределение каталогом.
package rules

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ShkodnikAI/NetAtlas/agent/collect"
)

var now = time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)

func testEngine(t *testing.T) *Engine {
	t.Helper()
	e, err := NewEngine("")
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return e
}

func report(tb testing.TB, mutate func(*collect.Report)) *collect.Report {
	tb.Helper()
	inv := &collect.Report{
		InventorySchemaVersion: collect.SchemaVersion,
		CollectedAt:            now.Format(time.RFC3339),
		Hostname:               "pc-1",
	}
	if mutate != nil {
		mutate(inv)
	}
	return inv
}

func ruleByID(t *testing.T, e *Engine, id string) Rule {
	t.Helper()
	for _, r := range e.SortedRules() {
		if r.ID == id {
			return r
		}
	}
	t.Fatalf("правило %s не найдено", id)
	return Rule{}
}

func findingsFor(t *testing.T, e *Engine, inv *collect.Report, ruleID string) []Finding {
	t.Helper()
	out := []Finding{}
	for _, f := range e.Evaluate(inv, now) {
		if f.RuleID == ruleID {
			out = append(out, f)
		}
	}
	return out
}

// ОЗУ: ровно порог — тихо, чуть ниже — замечание.
func TestRuleRAMLow(t *testing.T) {
	e := testEngine(t)
	r := ruleByID(t, e, "ram_low")
	cases := []struct {
		bytes string
		want  bool
	}{
		{"8589934592", false},  // ровно 8 ГБ
		{"8589934591", true},   // байт ниже порога
		{"4294967296", true},   // 4 ГБ
		{"17179869184", false}, // 16 ГБ
	}
	for _, c := range cases {
		inv := report(t, func(x *collect.Report) {
			x.Hardware = &collect.Hardware{TotalPhysicalMemory: c.bytes}
		})
		got := findingsFor(t, e, inv, "ram_low")
		if (len(got) > 0) != c.want {
			t.Fatalf("ОЗУ %s: замечаний %d, хочу %v", c.bytes, len(got), c.want)
		}
		if len(got) > 0 {
			if got[0].Advice != r.Advice || got[0].Severity != r.Severity {
				t.Fatalf("совет/серьёзность из правила: %+v", got[0])
			}
			if got[0].Source == "" {
				t.Fatal("замечание без source")
			}
		}
	}
	// Нет железа — нет замечания.
	if got := findingsFor(t, e, report(t, nil), "ram_low"); len(got) != 0 {
		t.Fatalf("без hardware: %v", got)
	}
}

// Износ SSD: 80 — тихо, 81 — замечание; HDD без счётчиков молчит.
func TestRuleSSDWear(t *testing.T) {
	e := testEngine(t)
	wear := func(w *int) *collect.Report {
		return report(t, func(x *collect.Report) {
			x.Disks = &collect.Disks{Disks: []collect.Disk{
				{FriendlyName: "SSD A", MediaType: "SSD", Wear: w},
			}}
		})
	}
	if got := findingsFor(t, e, wear(intPtr(80)), "ssd_wear_high"); len(got) != 0 {
		t.Fatalf("ровно порог: %v", got)
	}
	if got := findingsFor(t, e, wear(intPtr(79)), "ssd_wear_high"); len(got) != 0 {
		t.Fatalf("ниже порога: %v", got)
	}
	got := findingsFor(t, e, wear(intPtr(81)), "ssd_wear_high")
	if len(got) != 1 || got[0].Priority != 40*8.1 {
		t.Fatalf("выше порога: %+v (priority %v)", got, func() any {
			if len(got) > 0 {
				return got[0].Priority
			}
			return nil
		}())
	}
	if got := findingsFor(t, e, wear(nil), "ssd_wear_high"); len(got) != 0 {
		t.Fatalf("счётчики отсутствуют: %v", got)
	}
}

// Температура диска: 70 — тихо, 71 — замечание.
func TestRuleDiskTemp(t *testing.T) {
	e := testEngine(t)
	temp := func(v *int) *collect.Report {
		return report(t, func(x *collect.Report) {
			x.Disks = &collect.Disks{Disks: []collect.Disk{{FriendlyName: "Disk", Temperature: v}}}
		})
	}
	if got := findingsFor(t, e, temp(intPtr(70)), "disk_temp_high"); len(got) != 0 {
		t.Fatalf("ровно порог: %v", got)
	}
	if got := findingsFor(t, e, temp(intPtr(71)), "disk_temp_high"); len(got) != 1 {
		t.Fatalf("выше порога: %v", got)
	}
}

// Windows 10: поддержка закончилась 2025-10-14 — critical.
func TestRuleOSOutOfSupport(t *testing.T) {
	e := testEngine(t)
	inv := report(t, func(x *collect.Report) {
		x.OS = &collect.OSInfo{Caption: "Microsoft Windows 10 Pro", BuildNumber: "19045"}
	})
	got := findingsFor(t, e, inv, "os_out_of_support")
	if len(got) != 1 {
		t.Fatalf("замечаний %d, хочу 1: %v", len(got), got)
	}
	if got[0].Severity != "critical" {
		t.Fatalf("серьёзность %q, хочу critical", got[0].Severity)
	}
	if got[0].Priority != 100*10 {
		t.Fatalf("приоритет %v, хочу 1000", got[0].Priority)
	}
}

// Windows 11 24H2 (Home/Pro): EOL 2026-10-13 — уже истёк на now.
func TestRuleWin11_24H2Expired(t *testing.T) {
	e := testEngine(t)
	inv := report(t, func(x *collect.Report) {
		x.OS = &collect.OSInfo{Caption: "Microsoft Windows 11 Pro", BuildNumber: "26100"}
	})
	got := findingsFor(t, e, inv, "os_out_of_support")
	if len(got) != 1 || got[0].Severity != "critical" {
		t.Fatalf("24H2 Home/Pro вне поддержки: %v", got)
	}
	// Enterprise той же сборки живёт до 2027-10-12 — в пределах 180
	// дней? 2026-10-24 + 180 = 2027-04-22 — нет, дальше порога: тихо.
	invEnt := report(t, func(x *collect.Report) {
		x.OS = &collect.OSInfo{Caption: "Microsoft Windows 11 Enterprise", BuildNumber: "26100"}
	})
	if got := findingsFor(t, e, invEnt, "os_out_of_support"); len(got) != 0 {
		t.Fatalf("Enterprise 24H2 не должен попадать до 2027-04: %v", got)
	}
}

// Windows 11 23H2 Enterprise: EOL 2026-11-10 — 17 дней, warning.
func TestRuleWin11_23H2EnterpriseSoon(t *testing.T) {
	e := testEngine(t)
	inv := report(t, func(x *collect.Report) {
		x.OS = &collect.OSInfo{Caption: "Microsoft Windows 11 Enterprise", BuildNumber: "22631"}
	})
	got := findingsFor(t, e, inv, "os_out_of_support")
	if len(got) != 1 || got[0].Severity != "warning" {
		t.Fatalf("23H2 Enterprise скоро вне поддержки: %v", got)
	}
}

// Непроверенная строка таблицы не даёт замечаний серьёзнее info.
func TestRuleUnverifiedCapped(t *testing.T) {
	e := testEngine(t)
	// Официальная строка Windows 10 помечается непроверенной.
	for i := range e.table.OS {
		if e.table.OS[i].CaptionContains == "Windows 10" {
			e.table.OS[i].Verified = false
		}
	}
	inv := report(t, func(x *collect.Report) {
		x.OS = &collect.OSInfo{Caption: "Windows 10 Pro", BuildNumber: "19045"}
	})
	got := findingsFor(t, e, inv, "os_out_of_support")
	if len(got) != 1 {
		t.Fatalf("замечаний %d", len(got))
	}
	if len(got) != 1 || got[0].Severity != "info" {
		t.Fatalf("непроверенная строка не должна давать critical: %+v", got)
	}
	if got[0].Priority != 10*10 {
		t.Fatalf("приоритет info: %v", got[0].Priority)
	}
}

// Обновления: 60 дней — тихо, 61 — замечание; непарсируемая дата — тихо.
func TestRuleUpdatesStale(t *testing.T) {
	e := testEngine(t)
	hotfix := func(date string) *collect.Report {
		return report(t, func(x *collect.Report) {
			x.OS = &collect.OSInfo{LatestHotfix: date}
		})
	}
	if got := findingsFor(t, e, hotfix(now.Add(-60*24*time.Hour).Format("02.01.2006 15:04:05")), "os_updates_stale"); len(got) != 0 {
		t.Fatalf("ровно 60 дней: %v", got)
	}
	if got := findingsFor(t, e, hotfix(now.Add(-61*24*time.Hour).Format("02.01.2006 15:04:05")), "os_updates_stale"); len(got) != 1 {
		t.Fatalf("61 день: %v", got)
	}
	if got := findingsFor(t, e, hotfix("вчера или позавчера"), "os_updates_stale"); len(got) != 0 {
		t.Fatalf("непарсируемая дата должна молчать: %v", got)
	}
}

// Свободное место на системном томе: 15% — тихо, 14.9% — замечание.
func TestRuleVolumeFree(t *testing.T) {
	e := testEngine(t)
	vol := func(remaining string) *collect.Report {
		return report(t, func(x *collect.Report) {
			x.Disks = &collect.Disks{Volumes: []collect.Volume{
				{DriveLetter: "C", Size: "1000000000000", SizeRemaining: remaining},
			}}
		})
	}
	if got := findingsFor(t, e, vol("150000000000"), "volume_free_low"); len(got) != 0 {
		t.Fatalf("ровно 15%%: %v", got)
	}
	got := findingsFor(t, e, vol("149000000000"), "volume_free_low")
	if len(got) != 1 {
		t.Fatalf("ниже 15%%: %v", got)
	}
	// Не системный том не проверяется.
	other := report(t, func(x *collect.Report) {
		x.Disks = &collect.Disks{Volumes: []collect.Volume{
			{DriveLetter: "D", Size: "100", SizeRemaining: "1"},
		}}
	})
	if got := findingsFor(t, e, other, "volume_free_low"); len(got) != 0 {
		t.Fatalf("том D: %v", got)
	}
}

// Драйверы сетевой карты/видеокарты старше 3 лет — info.
func TestRuleDriversOld(t *testing.T) {
	e := testEngine(t)
	inv := report(t, func(x *collect.Report) {
		x.Drivers = []collect.Driver{
			{DeviceName: "Intel(R) UHD Graphics 630", Version: "31.0", Date: "2022-03-01"},
			{DeviceName: "Realtek PCIe GbE Family Controller", Version: "10.5", Date: "2020-01-15"},
			{DeviceName: "USB Input Device", Version: "1.0", Date: "2001-01-01"}, // не сеть/видео
			{DeviceName: "Wi-Fi 6 AX201", Version: "23.1", Date: "2026-01-01"},   // свежий
			{DeviceName: "Старый сетевой", Version: "1", Date: "миллион лет"},    // непарсируемое
		}
	})
	got := findingsFor(t, e, inv, "drivers_old")
	if len(got) != 2 {
		t.Fatalf("замечаний %d, хочу 2 (видео + сеть): %+v", len(got), got)
	}
	for _, f := range got {
		if f.Severity != "info" {
			t.Fatalf("драйверы — info: %+v", f)
		}
	}
}

// Поколение CPU: i5-10400 (10-е) — тихо; i5-7500 (7-е) — замечание;
// Ryzen 3600 — тихо; Ryzen 1700 — замечание; неизвестный — тихо.
func TestRuleCPUGeneration(t *testing.T) {
	e := testEngine(t)
	cases := []struct {
		name string
		want bool
	}{
		{"Intel(R) Core(TM) i5-10400 CPU @ 2.90GHz", false},
		{"Intel(R) Core(TM) i5-7500 CPU @ 3.40GHz", true},
		{"Intel(R) Core(TM) Ultra 7 265K", false},
		{"AMD Ryzen 5 3600 6-Core Processor", false},
		{"AMD Ryzen 7 1700 Eight-Core Processor", true},
		{" VIA C7-D Processor ", false},
	}
	for _, c := range cases {
		inv := report(t, func(x *collect.Report) {
			x.Hardware = &collect.Hardware{CPUs: []collect.CPU{{Name: c.name}}}
		})
		got := findingsFor(t, e, inv, "cpu_generation_old")
		if (len(got) > 0) != c.want {
			t.Fatalf("CPU %q: замечаний %d, хочу %v", c.name, len(got), c.want)
		}
	}
}

// Загрузчик отвергает правило без source.
func TestLoaderRejectsRuleWithoutSource(t *testing.T) {
	dir := t.TempDir()
	for _, f := range []string{"rules.json", "network.json", "os_lifecycle.json", "cpu_generations.json"} {
		raw, err := os.ReadFile(filepath.Join("data", f))
		if err != nil {
			t.Fatalf("чтение %s: %v", f, err)
		}
		if err := os.WriteFile(filepath.Join(dir, f), raw, 0o600); err != nil {
			t.Fatalf("копия %s: %v", f, err)
		}
	}
	// Ломаем source у первого правила.
	raw, _ := os.ReadFile(filepath.Join(dir, "rules.json"))
	broken := replaceFirst(raw, `"source": ["hardware.total_physical_memory", "hardware.memory_modules"]`, `"source": []`)
	if err := os.WriteFile(filepath.Join(dir, "rules.json"), broken, 0o600); err != nil {
		t.Fatalf("запись: %v", err)
	}
	if _, err := NewEngineDir(dir); err == nil {
		t.Fatal("правило без source принято загрузчиком")
	}
}

// Переопределение каталогом: правило из каталога действует.
func TestRulesDirOverride(t *testing.T) {
	dir := t.TempDir()
	for _, f := range []string{"network.json", "os_lifecycle.json", "cpu_generations.json"} {
		raw, err := os.ReadFile(filepath.Join("data", f))
		if err != nil {
			t.Fatalf("чтение %s: %v", f, err)
		}
		if err := os.WriteFile(filepath.Join(dir, f), raw, 0o600); err != nil {
			t.Fatalf("копия %s: %v", f, err)
		}
	}
	custom := []byte(`{"rules":[{"id":"ram_low","severity":"critical",
		"advice":"Своя рекомендация из каталога правил.",
		"source":["hardware.total_physical_memory"],"params":{"min_gb":64}}]}`)
	if err := os.WriteFile(filepath.Join(dir, "rules.json"), custom, 0o600); err != nil {
		t.Fatalf("запись: %v", err)
	}
	e, err := NewEngineDir(dir)
	if err != nil {
		t.Fatalf("NewEngineDir: %v", err)
	}
	inv := report(t, func(x *collect.Report) {
		x.Hardware = &collect.Hardware{TotalPhysicalMemory: "17179869184"} // 16 ГБ
	})
	got := findingsFor(t, e, inv, "ram_low")
	if len(got) != 1 || got[0].Severity != "critical" || got[0].Advice != "Своя рекомендация из каталога правил." {
		t.Fatalf("переопределение не сработало: %+v", got)
	}
}

// replaceFirst — замена первой подстроки (для тестов).
func replaceFirst(src []byte, old, new string) []byte {
	s := string(src)
	idx := indexOfStr(s, old)
	if idx < 0 {
		return src
	}
	return []byte(s[:idx] + new + s[idx+len(old):])
}

func indexOfStr(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
