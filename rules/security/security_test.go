// Оценка безопасности (NR-010): веса, границы, воспроизводимость.
// Тот же вход — тот же результат; неизвестные статусы не считаются
// «безопасными»; замечания без веса оценку не меняют.
package security

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/ShkodnikAI/NetAtlas/agent/checks"
	"github.com/ShkodnikAI/NetAtlas/rules"
)

func testEngine(t *testing.T) *Engine {
	t.Helper()
	re, err := rules.NewEngine("")
	if err != nil {
		t.Fatalf("движок правил: %v", err)
	}
	return NewEngine(re)
}

func TestEvaluateChecksFailOnly(t *testing.T) {
	e := testEngine(t)
	results := []checks.Result{
		{ID: checks.CheckSMBv1, Status: checks.StatusFail, Detail: "SMBv1 включён"},
		{ID: checks.CheckFirewall, Status: checks.StatusPass},
		{ID: checks.CheckBitLocker, Status: checks.StatusUnknown, Detail: "командлета нет"},
		{ID: checks.CheckPorts, Status: checks.StatusPass, Detail: "слушающих портов: 3"},
	}
	fs := e.EvaluateChecks(results, "agent:x", "2026-10-24T00:00:00Z")
	if len(fs) != 1 {
		t.Fatalf("замечаний: %d, ждём 1 (pass и unknown не замечания): %+v", len(fs), fs)
	}
	f := fs[0]
	if f.RuleID != "sec_smbv1_enabled" || f.Severity != "critical" || f.Weight != 25 {
		t.Fatalf("замечание: %+v", f)
	}
	if f.Fact != "Включён устаревший протокол SMBv1: SMBv1 включён" {
		t.Fatalf("fact: %q", f.Fact)
	}
	if f.Basis == "" || f.Advice == "" {
		t.Fatalf("основание и совет обязательны: %+v", f)
	}
}

func TestEvaluateChecksUnknownIsNotSafe(t *testing.T) {
	// unknown не даёт замечания и не снижает оценку: он виден в
	// сводке как «не определено».
	e := testEngine(t)
	fs := e.EvaluateChecks([]checks.Result{
		{ID: checks.CheckDefender, Status: checks.StatusUnknown, Detail: "командлета нет"},
	}, "agent:x", "2026-10-24T00:00:00Z")
	if len(fs) != 0 {
		t.Fatalf("unknown дал замечание: %+v", fs)
	}
}

func TestScoreBoundaries(t *testing.T) {
	e := testEngine(t)
	if got := e.Score(nil); got != 100 {
		t.Fatalf("без замечаний оценка 100, получена %d", got)
	}
	fs := []Finding{
		{RuleID: "sec_smbv1_enabled", Weight: 25},
		{RuleID: "sec_rdp_no_nla", Weight: 20},
	}
	if got := e.Score(fs); got != 55 {
		t.Fatalf("100-25-20 = 55, получена %d", got)
	}
	// Сумма весов больше 100: оценка не уходит ниже нуля.
	many := []Finding{}
	for i := 0; i < 6; i++ {
		many = append(many, Finding{RuleID: "sec_smbv1_enabled", Weight: 25})
	}
	if got := e.Score(many); got != 0 {
		t.Fatalf("оценка ограничена нулём, получена %d", got)
	}
	// Замечание без записи в таблице весов оценку не меняет.
	if got := e.Score([]Finding{{RuleID: "no_such_rule", Weight: 50}}); got != 100 {
		t.Fatalf("неизвестное правило не влияет на оценку, получена %d", got)
	}
}

func TestScoreDeterministic(t *testing.T) {
	e := testEngine(t)
	fs := []Finding{
		{RuleID: "sec_firewall_off", Weight: 20},
		{RuleID: "sec_smbv1_enabled", Weight: 25},
		{RuleID: "sec_bitlocker_off", Weight: 15},
	}
	first := e.Score(fs)
	for i := 0; i < 5; i++ {
		if got := e.Score(fs); got != first {
			t.Fatalf("оценка зависит от порядка: %d против %d", got, first)
		}
	}
}

func TestEvaluateSoftware(t *testing.T) {
	e := testEngine(t)
	programs := []Software{
		{Name: "Adobe Acrobat Reader DC", Version: "21.0"},
		{Name: "Google Chrome", Version: "132.0"}, // свежее минимума
		{Name: "Mozilla Firefox", Version: "132.0"},
		{Name: "7-Zip 24.08 (x64)", Version: "24.08"},
		{Name: "Софт без версии", Version: ""},
	}
	fs := e.EvaluateSoftware(programs, "agent:x", "2026-10-24T00:00:00Z")
	if len(fs) != 1 {
		t.Fatalf("замечаний: %d, ждём 1: %+v", len(fs), fs)
	}
	if fs[0].Fact != "Устаревшее ПО из таблицы минимальных версий: Adobe Acrobat Reader DC 21.0" {
		t.Fatalf("fact: %q", fs[0].Fact)
	}
	if fs[0].Severity != "warning" {
		t.Fatalf("verified=true → warning, получен %q", fs[0].Severity)
	}
	// Ровно минимальная версия — не замечание (граница).
	fs = e.EvaluateSoftware([]Software{{Name: "Adobe Acrobat Reader", Version: "24.0"}},
		"agent:x", "2026-10-24T00:00:00Z")
	if len(fs) != 0 {
		t.Fatalf("версия равна минимуму — не замечание: %+v", fs)
	}
	// Сегменты: 24 < 24.0.1.
	fs = e.EvaluateSoftware([]Software{{Name: "Adobe Acrobat Reader", Version: "24.0.0"}},
		"agent:x", "2026-10-24T00:00:00Z")
	if len(fs) != 0 {
		t.Fatalf("24.0.0 == 24.0 — не замечание: %+v", fs)
	}
}

func TestParseVersion(t *testing.T) {
	cases := []struct {
		in   string
		want []int
		ok   bool
	}{
		{"24.0", []int{24, 0}, true},
		{" 132.0.6853.0 ", []int{132, 0, 6853, 0}, true},
		{"24.08", []int{24, 8}, true},
		{"10.1.2 (сборка 3)", []int{10, 1, 2}, true},
		{"", nil, false},
		{"не версия", nil, false},
		{"v24.0", nil, false}, // нечисловой сегмент — не версия, суждения нет
	}
	for _, c := range cases {
		got, ok := parseVersion(c.in)
		if ok != c.ok || (ok && !reflect.DeepEqual(got, c.want)) {
			t.Fatalf("parseVersion(%q) = %v, %v; ждём %v, %v", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestEvaluateNetwork(t *testing.T) {
	e := testEngine(t)
	devs := []NetworkDevice{
		{ID: "aa:bb:cc:dd:ee:01", Label: "Коммутатор коридор", Sources: []string{"ping", "snmp", "snmp_v2c"}},
		{ID: "aa:bb:cc:dd:ee:02", Sources: []string{"ping", "snmp"}}, // только v3
		{ID: "aa:bb:cc:dd:ee:03", Sources: []string{"ping"}},
	}
	fs := e.EvaluateNetwork(devs)
	if len(fs) != 3 {
		t.Fatalf("замечаний: %d, ждём 3: %+v", len(fs), fs)
	}
	// Детерминированный порядок: sec_snmp_admin_open раньше sec_snmp_v2c_enabled.
	if fs[0].RuleID != "sec_snmp_admin_open" || fs[1].RuleID != "sec_snmp_admin_open" || fs[2].RuleID != "sec_snmp_v2c_enabled" {
		t.Fatalf("порядок замечаний: %s, %s, %s", fs[0].RuleID, fs[1].RuleID, fs[2].RuleID)
	}
	// Одинаковые правила различаются источником: сортировка по
	// (правило, факт, источник) даёт ee:01 раньше ee:02.
	if fs[0].Source != "scan:observations aa:bb:cc:dd:ee:01" {
		t.Fatalf("source[0]: %q", fs[0].Source)
	}
	if fs[1].Source != "scan:observations aa:bb:cc:dd:ee:02" {
		t.Fatalf("source[1]: %q", fs[1].Source)
	}
	if fs[2].Severity != "warning" {
		t.Fatalf("v2c — warning, получен %q", fs[2].Severity)
	}
}

func TestDeterministicJSON(t *testing.T) {
	// Один и тот же вход — байт в байт тот же вывод (наряд требует
	// воспроизводимости оценки).
	e := testEngine(t)
	results := []checks.Result{
		{ID: checks.CheckSMBv1, Status: checks.StatusFail, Detail: "SMBv1 включён"},
		{ID: checks.CheckFirewall, Status: checks.StatusFail, Detail: "профиль выключен: Public"},
	}
	programs := []Software{
		{Name: "Google Chrome", Version: "90.0"},
		{Name: "Adobe Reader", Version: "20.0"},
	}
	one := evaluateAll(e, results, programs)
	for i := 0; i < 3; i++ {
		two := evaluateAll(e, results, programs)
		if string(one) != string(two) {
			t.Fatalf("вывод зависит от чего-то ещё, кроме входа:\n%s\n%s", one, two)
		}
	}
}

func evaluateAll(e *Engine, results []checks.Result, programs []Software) []byte {
	fs := append(e.EvaluateChecks(results, "agent:x", "2026-10-24T00:00:00Z"),
		e.EvaluateSoftware(programs, "agent:x", "2026-10-24T00:00:00Z")...)
	score := e.Score(fs)
	out, err := json.Marshal(map[string]any{"findings": fs, "score": score})
	if err != nil {
		panic(err)
	}
	return out
}
