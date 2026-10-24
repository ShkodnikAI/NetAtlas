// Package security — оценка безопасности (NR-010): разбор отчётов
// проверок агентов, замечания по инвентарю (ПО против таблицы
// версий) и по сетевым наблюдениям сканера, детерминированная
// оценка 0–100 по весам. Все функции чистые: один и тот же вход
// даёт один и тот же результат (тест). Активных проб здесь нет:
// только то, что уже собрали агенты и сканер.
package security

import (
	"sort"
	"strconv"
	"strings"

	"github.com/ShkodnikAI/NetAtlas/agent/checks"
	"github.com/ShkodnikAI/NetAtlas/rules"
)

// Finding — замечание безопасности: то же правило, что и в NR-009,
// плюс основание (публичный источник) и вес.
type Finding struct {
	RuleID   string  `json:"rule_id"`
	Severity string  `json:"severity"`
	Fact     string  `json:"fact"`
	Source   string  `json:"source"`
	Advice   string  `json:"advice"`
	Basis    string  `json:"basis"`
	BasisURL string  `json:"basis_url,omitempty"`
	Weight   int     `json:"weight"`
	Priority float64 `json:"priority"`
}

// Engine — веса безопасности и таблица ПО; тонкая обёртка над
// движком правил (данные одни и те же, --rules-dir учитывается).
type Engine struct {
	r *rules.Engine
}

// NewEngine оборачивает движок правил.
func NewEngine(re *rules.Engine) *Engine { return &Engine{r: re} }

// rule — запись веса для идентификатора; нет записи — проверка не
// участвует в оценке (факт остаётся в отчёте агента).
func (e *Engine) rule(id string) (rules.SecRule, bool) {
	return e.r.SecurityRule(id)
}

// Rule — публичный доступ к записи веса (серверный API переиспользует
// советы и основания для замечаний инвентаря).
func (e *Engine) Rule(id string) (rules.SecRule, bool) { return e.rule(id) }

// EvaluateChecks — замечания по отчёту проверок агента. Статусы
// pass и unknown замечаний не дают: unknown — «не определено», а
// не «безопасно»; он виден в сводке отдельным счётчиком.
func (e *Engine) EvaluateChecks(results []checks.Result, agentID, collectedAt string) []Finding {
	out := []Finding{}
	for _, res := range results {
		if res.Status != checks.StatusFail {
			continue
		}
		sec, ok := e.rule(checkRuleID(res.ID))
		if !ok {
			continue // проверка без веса: факт виден в карточке, оценку не меняет
		}
		out = append(out, Finding{
			RuleID:   checkRuleID(res.ID),
			Severity: sec.Severity,
			Fact:     factOf(sec.Title, res.Detail),
			Source:   "agent:check " + res.ID + " @ " + collectedAt,
			Advice:   sec.Advice,
			Basis:    sec.Basis,
			BasisURL: sec.BasisURL,
			Weight:   sec.Weight,
			Priority: float64(sec.Weight),
		})
	}
	sortFindings(out)
	return out
}

// checkRuleID — идентификатор правила для проверки агента.
func checkRuleID(checkID string) string {
	switch checkID {
	case checks.CheckSMBv1:
		return "sec_smbv1_enabled"
	case checks.CheckBitLocker:
		return "sec_bitlocker_off"
	case checks.CheckRDPNLA:
		return "sec_rdp_no_nla"
	case checks.CheckFirewall:
		return "sec_firewall_off"
	case checks.CheckDefender:
		return "sec_defender_off"
	default:
		return checkID // проверки без правила (например, ports)
	}
}

// factOf — текст замечания: заголовок правила и факт проверки.
func factOf(title, detail string) string {
	if detail == "" {
		return title
	}
	return title + ": " + detail
}

// EvaluateSoftware — установленное ПО против таблицы минимально
// допустимых версий. Программа без версии или с нечисловой версией
// не даёт замечания (не выдумывать). Записи с verified=false дают
// замечание не серьёзнее info.
func (e *Engine) EvaluateSoftware(programs []Software, agentID, collectedAt string) []Finding {
	out := []Finding{}
	for _, row := range e.r.SoftwareRows() {
		minVer, ok := parseVersion(row.MinVersion)
		if !ok {
			continue // строка таблицы без версии не срабатывает
		}
		var hits []string
		for _, p := range programs {
			if !matches(p.Name, row.MatchContains) {
				continue
			}
			ver, ok := parseVersion(p.Version)
			if !ok {
				continue // версии нет — суждения нет
			}
			if versionLess(ver, minVer) {
				hits = append(hits, p.Name+" "+p.Version)
			}
		}
		if len(hits) == 0 {
			continue
		}
		sec, ok := e.rule("sec_software_outdated")
		if !ok {
			continue
		}
		severity := sec.Severity
		if !row.Verified {
			severity = rules.SeverityInfo
		}
		out = append(out, Finding{
			RuleID:   "sec_software_outdated",
			Severity: severity,
			Fact:     factOf(sec.Title, strings.Join(hits, ", ")),
			Source:   "inventory:programs @ " + collectedAt,
			Advice:   sec.Advice,
			Basis:    sec.Basis + " (" + row.Title + ": " + row.SourceURL + ")",
			Weight:   sec.Weight,
			Priority: float64(sec.Weight),
		})
	}
	sortFindings(out)
	return out
}

// Software — установленная программа (из отчёта инвентаря).
type Software struct {
	Name    string
	Version string
}

// matches — имя программы совпадает с любой подстрокой строки
// таблицы без учёта регистра.
func matches(name string, patterns []string) bool {
	lower := strings.ToLower(name)
	for _, p := range patterns {
		if strings.Contains(lower, strings.ToLower(p)) {
			return true
		}
	}
	return false
}

// parseVersion — «24.0.1.7» → [24,0,1,7]; нечисловой хвост
// отбрасывается, полностью нечисловая строка — не версия.
func parseVersion(s string) ([]int, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, false
	}
	var out []int
	for _, seg := range strings.Split(s, ".") {
		digits := 0
		for _, c := range seg {
			if c < '0' || c > '9' {
				break
			}
			digits++
		}
		if digits == 0 {
			break
		}
		n, err := strconv.Atoi(seg[:digits])
		if err != nil {
			break
		}
		out = append(out, n)
	}
	return out, len(out) > 0
}

// versionLess — строго меньше: посегментно, недостающие сегменты —
// нули («24.0» == «24.0.0»).
func versionLess(a, b []int) bool {
	n := len(a)
	if len(b) > n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		av, bv := 0, 0
		if i < len(a) {
			av = a[i]
		}
		if i < len(b) {
			bv = b[i]
		}
		if av != bv {
			return av < bv
		}
	}
	return false
}

// NetworkDevice — устройство карты с наблюдениями сканера.
type NetworkDevice struct {
	ID      string
	Label   string
	Klass   string
	Sources []string // источники наблюдений (ping, snmp, snmp_v2c, …)
}

// EvaluateNetwork — замечания по сетевым устройствам из данных
// сканера. Никаких новых проб: только уже собранные наблюдения.
// Наблюдение «snmp» — устройство ответило на опрос SNMP (интерфейс
// управления доступен по сети); «snmp_v2c» — при этом опрос шёл по
// SNMPv1/v2c (небезопасная версия).
func (e *Engine) EvaluateNetwork(devs []NetworkDevice) []Finding {
	out := []Finding{}
	for _, d := range devs {
		has := map[string]bool{}
		for _, s := range d.Sources {
			has[s] = true
		}
		label := d.Label
		if label == "" {
			label = d.ID
		}
		if has["snmp"] {
			if sec, ok := e.rule("sec_snmp_admin_open"); ok {
				out = append(out, Finding{
					RuleID:   "sec_snmp_admin_open",
					Severity: sec.Severity,
					Fact:     factOf(sec.Title, "устройство отвечает на опрос SNMP"),
					Source:   "scan:observations " + d.ID,
					Advice:   sec.Advice,
					Basis:    sec.Basis,
					BasisURL: sec.BasisURL,
					Weight:   sec.Weight,
					Priority: float64(sec.Weight),
				})
			}
		}
		if has["snmp_v2c"] {
			if sec, ok := e.rule("sec_snmp_v2c_enabled"); ok {
				out = append(out, Finding{
					RuleID:   "sec_snmp_v2c_enabled",
					Severity: sec.Severity,
					Fact:     factOf(sec.Title, "опрос сканера прошёл по SNMPv1/v2c"),
					Source:   "scan:observations " + d.ID,
					Advice:   sec.Advice,
					Basis:    sec.Basis,
					BasisURL: sec.BasisURL,
					Weight:   sec.Weight,
					Priority: float64(sec.Weight),
				})
			}
		}
	}
	sortFindings(out)
	return out
}

// Score — оценка 0–100: 100 минус сумма весов замечаний, не меньше
// нуля. Веса замечаний без записи в таблице не вычитаются.
func (e *Engine) Score(findings []Finding) int {
	total := 100
	for _, f := range findings {
		if sec, ok := e.rule(f.RuleID); ok && sec.Weight > 0 {
			total -= sec.Weight
		}
	}
	if total < 0 {
		return 0
	}
	if total > 100 {
		return 100
	}
	return total
}

// sortFindings — детерминированный порядок: правило, факт,
// источник (факты совпадающих правил различаются источниками).
func sortFindings(out []Finding) {
	sort.Slice(out, func(i, j int) bool {
		if out[i].RuleID != out[j].RuleID {
			return out[i].RuleID < out[j].RuleID
		}
		if out[i].Fact != out[j].Fact {
			return out[i].Fact < out[j].Fact
		}
		return out[i].Source < out[j].Source
	})
}
