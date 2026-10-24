// Вычислитель правил (NR-009): инвентарь агента → замечания.
// Каждый факт — из поля инвентаря с временем сбора; совет — из
// правила (не генерируется). Строки таблиц с verified=false не дают
// замечаний серьёзнее info.
package rules

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ShkodnikAI/NetAtlas/agent/collect"
)

// Finding — одно замечание.
type Finding struct {
	RuleID    string  `json:"rule_id"`
	Severity  string  `json:"severity"`
	Fact      string  `json:"fact"`
	Threshold string  `json:"threshold,omitempty"`
	Source    string  `json:"source"`
	Advice    string  `json:"advice"`
	Priority  float64 `json:"priority"`
}

// Urgency — срочность 1..10 (умножается на вес серьёзности,
// docs/RULES.md). Ограничение сверху защищает от разгона.
func Urgency(u float64) float64 {
	if u < 1 {
		return 1
	}
	if u > 10 {
		return 10
	}
	return u
}

func finding(r Rule, fact, threshold, source string, urgency float64) Finding {
	return Finding{
		RuleID:    r.ID,
		Severity:  r.Severity,
		Fact:      fact,
		Threshold: threshold,
		Source:    source,
		Advice:    r.Advice,
		Priority:  severityWeight(r.Severity) * Urgency(urgency),
	}
}

// Evaluate — все правила по отчёту инвентаря.
func (e *Engine) Evaluate(inv *collect.Report, now time.Time) []Finding {
	out := []Finding{}
	for _, r := range e.table.Rules {
		switch r.ID {
		case "ram_low":
			out = append(out, e.ramLow(r, inv, now)...)
		case "ssd_wear_high":
			out = append(out, e.ssdWear(r, inv, now)...)
		case "disk_temp_high":
			out = append(out, e.diskTemp(r, inv, now)...)
		case "os_out_of_support":
			out = append(out, e.osLifecycle(r, inv, now)...)
		case "cpu_generation_old":
			out = append(out, e.cpuGeneration(r, inv, now)...)
		case "os_updates_stale":
			out = append(out, e.updatesStale(r, inv, now)...)
		case "volume_free_low":
			out = append(out, e.volumeFree(r, inv, now)...)
		case "drivers_old":
			out = append(out, e.driversOld(r, inv, now)...)
		}
	}
	// Детерминированный порядок: правило, потом факт.
	sort.Slice(out, func(i, j int) bool {
		if out[i].RuleID != out[j].RuleID {
			return out[i].RuleID < out[j].RuleID
		}
		return out[i].Fact < out[j].Fact
	})
	return out
}

func sourceOf(inv *collect.Report, field string) string {
	return field + " @ " + inv.CollectedAt
}

// gb — байты (строкой) в ГБ.
func gb(b string) float64 {
	n, err := strconv.ParseFloat(strings.TrimSpace(b), 64)
	if err != nil {
		return 0
	}
	return n / (1 << 30)
}

func (e *Engine) ramLow(r Rule, inv *collect.Report, now time.Time) []Finding {
	if inv.Hardware == nil {
		return nil
	}
	minGB := r.param("min_gb", 8)
	total := gb(inv.Hardware.TotalPhysicalMemory)
	if total <= 0 || total >= minGB {
		return nil
	}
	modules := len(inv.Hardware.MemoryModules)
	fact := fmt.Sprintf("ОЗУ %.1f ГБ (модулей: %d) — ниже порога %.0f ГБ", total, modules, minGB)
	return []Finding{finding(r, fact,
		fmt.Sprintf(">= %.0f ГБ", minGB), sourceOf(inv, "hardware.total_physical_memory"), 4)}
}

func (e *Engine) ssdWear(r Rule, inv *collect.Report, now time.Time) []Finding {
	if inv.Disks == nil {
		return nil
	}
	limit := int(r.param("wear_percent", 80))
	out := []Finding{}
	for _, d := range inv.Disks.Disks {
		if d.Wear == nil || *d.Wear <= limit {
			continue
		}
		fact := fmt.Sprintf("износ SSD %q — %d%%", d.FriendlyName, *d.Wear)
		out = append(out, finding(r, fact,
			fmt.Sprintf("<= %d%%", limit), sourceOf(inv, "disks.disks.wear"), float64(*d.Wear)/10))
	}
	return out
}

func (e *Engine) diskTemp(r Rule, inv *collect.Report, now time.Time) []Finding {
	if inv.Disks == nil {
		return nil
	}
	limit := int(r.param("temp_c", 70))
	out := []Finding{}
	for _, d := range inv.Disks.Disks {
		if d.Temperature == nil || *d.Temperature <= limit {
			continue
		}
		fact := fmt.Sprintf("температура диска %q — %d °C", d.FriendlyName, *d.Temperature)
		out = append(out, finding(r, fact,
			fmt.Sprintf("<= %d °C", limit), sourceOf(inv, "disks.disks.temperature"), float64(*d.Temperature)/10))
	}
	return out
}

// osEOL — срок поддержки по таблице: что истекло и что кончается в
// ближайшие N дней. Неизвестная сборка — не замечание.
func (e *Engine) osEOL(r Rule, inv *collect.Report, now time.Time) (eol time.Time, verified bool, name string) {
	if inv.OS == nil {
		return time.Time{}, false, ""
	}
	build := strings.TrimSpace(inv.OS.BuildNumber)
	caption := strings.ToLower(inv.OS.Caption)
	for _, row := range e.table.OS {
		matched := strings.Contains(caption, strings.ToLower(row.CaptionContains))
		if !matched {
			continue
		}
		prefixOK := false
		for _, p := range row.BuildPrefixes {
			if strings.HasPrefix(build, p) {
				prefixOK = true
				break
			}
		}
		if !prefixOK {
			continue
		}
		// Домашние редакции: Home/Pro. Enterprise/Education определяется
		// по подписи выпуска.
		ent := strings.Contains(caption, "enterprise") || strings.Contains(caption, "education") ||
			strings.Contains(caption, "ltsc")
		date := row.EOLHomePro
		if ent && row.EOLEntEdu != "" {
			date = row.EOLEntEdu
		}
		t, err := time.Parse("2006-01-02", date)
		if err != nil {
			return time.Time{}, false, ""
		}
		return t, row.Verified, row.Name
	}
	return time.Time{}, false, ""
}

func (e *Engine) osLifecycle(r Rule, inv *collect.Report, now time.Time) []Finding {
	eol, verified, name := e.osEOL(r, inv, now)
	if eol.IsZero() {
		return nil
	}
	daysAhead := int(r.param("days_ahead", 180))
	if !now.Before(eol) {
		// Срок истёк. Не подтверждённая строка не даёт critical.
		severity := r.Severity
		if !verified {
			severity = SeverityInfo
		}
		rule := r
		rule.Severity = severity
		fact := fmt.Sprintf("%s: поддержка закончилась %s", name, eol.Format("2006-01-02"))
		return []Finding{finding(rule, fact, eol.Format("2006-01-02"), sourceOf(inv, "os.build_number"), 10)}
	}
	days := int(eol.Sub(now).Hours() / 24)
	if days > daysAhead {
		return nil
	}
	// Скоро кончится: максимум warning, непроверенное — info.
	severity := SeverityWarning
	if !verified {
		severity = SeverityInfo
	}
	rule := r
	rule.Severity = severity
	urgency := 8.0
	if days > 30 {
		urgency = 5
	}
	if days > 90 {
		urgency = 3
	}
	fact := fmt.Sprintf("%s: поддержка кончается через %d дней (%s)", name, days, eol.Format("2006-01-02"))
	return []Finding{finding(rule, fact, fmt.Sprintf("<= %d дней", daysAhead), sourceOf(inv, "os.build_number"), urgency)}
}

// cpuGeneration — поколение процессора по имени и таблице.
func (e *Engine) cpuGeneration(r Rule, inv *collect.Report, now time.Time) []Finding {
	if inv.Hardware == nil {
		return nil
	}
	minIntel := int(r.param("min_generation_intel", 8))
	minAMD := int(r.param("min_series_amd", 2000))
	out := []Finding{}
	for _, cpu := range inv.Hardware.CPUs {
		name := cpu.Name
		lower := strings.ToLower(name)
		row, ok := e.matchCPU(lower)
		if !ok {
			continue // не по памяти: неизвестный производитель — не замечание
		}
		if row.Vendor == "Intel" {
			gen := intelGeneration(lower)
			if gen == 0 || gen >= minIntel {
				continue
			}
			severity := r.Severity
			if !row.Verified {
				severity = SeverityInfo
			}
			rule := r
			rule.Severity = severity
			fact := fmt.Sprintf("процессор %q — %d-е поколение, минимум в таблице: %d-е", name, gen, minIntel)
			out = append(out, finding(rule, fact,
				fmt.Sprintf(">= %d-го поколения", minIntel), sourceOf(inv, "hardware.cpus.name"), 2))
			continue
		}
		// AMD: серия из модели (Ryzen 5 3600 → 3000).
		series := amdSeries(lower)
		if series == 0 || series >= minAMD {
			continue
		}
		severity := r.Severity
		if !row.Verified {
			severity = SeverityInfo
		}
		rule := r
		rule.Severity = severity
		fact := fmt.Sprintf("процессор %q — серия %d00, минимум в таблице: %d00", name, series/100, minAMD/100)
		out = append(out, finding(rule, fact,
			fmt.Sprintf(">= %d00 серии", minAMD/100), sourceOf(inv, "hardware.cpus.name"), 2))
	}
	return out
}

// matchCPU — строка таблицы, совпавшая по подстроке.
func (e *Engine) matchCPU(lower string) (CPURow, bool) {
	for _, row := range e.table.CPU {
		for _, m := range row.MatchContains {
			if strings.Contains(lower, strings.ToLower(m)) {
				return row, true
			}
		}
	}
	return CPURow{}, false
}

// intelGeneration — поколение из модели: "i5-10400" → 10, "i7-8700" → 8.
// Core Ultra → 12 (линейка новее 11-го поколения).
func intelGeneration(lower string) int {
	if strings.Contains(lower, "ultra") {
		return 12
	}
	idx := strings.Index(lower, "-")
	if idx < 0 {
		return 0
	}
	digits := ""
	for _, c := range lower[idx+1:] {
		if c >= '0' && c <= '9' {
			digits += string(c)
		} else {
			break
		}
	}
	// Поколение — первая цифра(ы) модели: i5-10400 → 10, i7-8700 → 8.
	if len(digits) < 4 {
		return 0
	}
	n, err := strconv.Atoi(digits)
	if err != nil {
		return 0
	}
	return n / 1000
}

// amdSeries — серия Ryzen из модели: "ryzen 5 3600" → 3600 (серия 3000).
func amdSeries(lower string) int {
	idx := strings.LastIndex(lower, "ryzen")
	if idx < 0 {
		return 0
	}
	// Номер модели — первый токен из 4+ цифр после слова ryzen
	// ("ryzen 7 1700 eight-core" → 1700), не последнее слово.
	for _, f := range strings.Fields(lower[idx:]) {
		if len(f) < 4 {
			continue
		}
		allDigits := true
		for _, c := range f {
			if c < '0' || c > '9' {
				allDigits = false
				break
			}
		}
		if !allDigits {
			continue
		}
		n, err := strconv.Atoi(f)
		if err != nil {
			continue
		}
		return n / 100 * 100
	}
	return 0
}

// parseDateBestEffort — даты из локали: разбор в нескольких форматах,
// не разобралось — false (правило молчит, не выдумывает).
func parseDateBestEffort(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	layouts := []string{
		"2006-01-02",
		"02.01.2006 15:04:05",
		"02.01.2006",
		"1/2/2006 3:04:05 PM",
		"1/2/2006",
		"02.01.2006 15:04:05 -07:00",
		time.RFC3339,
	}
	for _, l := range layouts {
		if t, err := time.Parse(l, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

func (e *Engine) updatesStale(r Rule, inv *collect.Report, now time.Time) []Finding {
	if inv.OS == nil {
		return nil
	}
	staleDays := int(r.param("stale_days", 60))
	last, ok := parseDateBestEffort(inv.OS.LatestHotfix)
	if !ok {
		return nil // дату не разобрать — не замечание
	}
	days := int(now.Sub(last).Hours() / 24)
	if days <= staleDays {
		return nil
	}
	fact := fmt.Sprintf("последнее обновление ОС — %d дней назад (%s)", days, inv.OS.LatestHotfix)
	return []Finding{finding(r, fact,
		fmt.Sprintf("<= %d дней", staleDays), sourceOf(inv, "os.latest_hotfix"), float64(days)/10)}
}

func (e *Engine) volumeFree(r Rule, inv *collect.Report, now time.Time) []Finding {
	if inv.Disks == nil {
		return nil
	}
	freeLimit := r.param("free_percent", 15)
	drive := "C"
	if s, ok := r.Params["drive"].(string); ok && s != "" {
		drive = s
	}
	out := []Finding{}
	for _, v := range inv.Disks.Volumes {
		if !strings.EqualFold(v.DriveLetter, drive) {
			continue
		}
		size, err1 := strconv.ParseFloat(strings.TrimSpace(v.Size), 64)
		free, err2 := strconv.ParseFloat(strings.TrimSpace(v.SizeRemaining), 64)
		if err1 != nil || err2 != nil || size <= 0 {
			continue
		}
		freePct := free / size * 100
		if freePct >= freeLimit {
			continue
		}
		fact := fmt.Sprintf("на томе %s свободно %.1f%% (%.0f ГБ из %.0f ГБ)", v.DriveLetter, freePct, gb(v.SizeRemaining), gb(v.Size))
		out = append(out, finding(r, fact,
			fmt.Sprintf(">= %.0f%%", freeLimit), sourceOf(inv, "disks.volumes.size_remaining"), 10-freePct))
	}
	return out
}

// isVideoDriver / isNetDriver — подписи устройств.
func isVideoDriver(name string) bool {
	l := strings.ToLower(name)
	for _, m := range []string{"graphics", "video", "display", "vga", "geforce", "radeon", "uhd"} {
		if strings.Contains(l, m) {
			return true
		}
	}
	return false
}

func isNetDriver(name string) bool {
	l := strings.ToLower(name)
	for _, m := range []string{"network", "ethernet", "wi-fi", "wireless", "wlan", "gbe"} {
		if strings.Contains(l, m) {
			return true
		}
	}
	return false
}

func (e *Engine) driversOld(r Rule, inv *collect.Report, now time.Time) []Finding {
	years := r.param("years", 3)
	limit := now.AddDate(-int(years), 0, 0)
	out := []Finding{}
	for _, d := range inv.Drivers {
		if !isVideoDriver(d.DeviceName) && !isNetDriver(d.DeviceName) {
			continue
		}
		date, ok := parseDateBestEffort(d.Date)
		if !ok {
			continue
		}
		if date.After(limit) {
			continue
		}
		fact := fmt.Sprintf("драйвер %q (версия %s) от %s — старше %.0f лет", d.DeviceName, d.Version, date.Format("2006-01-02"), years)
		out = append(out, finding(r, fact,
			fmt.Sprintf("новее %.0f лет", years), sourceOf(inv, "drivers.date"), 1))
	}
	return out
}
