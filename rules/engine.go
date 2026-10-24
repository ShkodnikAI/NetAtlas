// Движок правил (NR-009): типы, загрузка встроенных правил
// (rules/data/*.json, go:embed) или каталога --rules-dir.
package rules

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"sort"
	"strings"
)

//go:embed data/rules.json data/network.json data/os_lifecycle.json data/cpu_generations.json
var dataFS embed.FS

// Severity — серьёзность замечания.
const (
	SeverityCritical = "critical"
	SeverityWarning  = "warning"
	SeverityInfo     = "info"
)

// severityWeight — вес серьёзности для приоритета (docs/RULES.md).
func severityWeight(s string) float64 {
	switch s {
	case SeverityCritical:
		return 100
	case SeverityWarning:
		return 40
	case SeverityInfo:
		return 10
	}
	return 0
}

// Rule — правило: порог, серьёзность и готовый совет.
type Rule struct {
	ID       string         `json:"id"`
	Severity string         `json:"severity"`
	Advice   string         `json:"advice"`
	Source   []string       `json:"source"`
	Params   map[string]any `json:"params,omitempty"`
}

// param — числовой параметр правила с дефолтом.
func (r Rule) param(key string, def float64) float64 {
	if v, ok := r.Params[key]; ok {
		if f, ok := v.(float64); ok {
			return f
		}
	}
	return def
}

// OSRow — строка таблицы сроков поддержки ОС.
type OSRow struct {
	Name            string   `json:"name"`
	CaptionContains string   `json:"caption_contains"`
	BuildPrefixes   []string `json:"build_prefixes"`
	EOLHomePro      string   `json:"eol_home_pro"`
	EOLEntEdu       string   `json:"eol_ent_edu"`
	SourceURL       string   `json:"source_url"`
	Checked         string   `json:"checked"`
	Verified        bool     `json:"verified"`
}

// CPURow — строка таблицы поколений процессоров.
type CPURow struct {
	Vendor          string   `json:"vendor"`
	Name            string   `json:"name"`
	MatchContains   []string `json:"match_contains"`
	Generation      int      `json:"generation"`
	SeriesThreshold bool     `json:"series_threshold"` // AMD: сравнение серии (2000), не поколения
	Note            string   `json:"note,omitempty"`
	SourceURL       string   `json:"source_url"`
	Checked         string   `json:"checked"`
	Verified        bool     `json:"verified"`
}

// Table — набор правил и справочных таблиц.
type Table struct {
	Rules   []Rule   `json:"rules"`
	Network []Rule   `json:"-"` // network.json (узкие места)
	OS      []OSRow  `json:"-"` // отдельный файл
	CPU     []CPURow `json:"-"`
}

// Engine — загруженные правила и таблицы.
type Engine struct {
	table Table
}

// validate — правило обязано иметь id, severity, advice и source:
// замечание без источника не имеет силы.
func validateRule(r Rule) error {
	if strings.TrimSpace(r.ID) == "" {
		return fmt.Errorf("правило без id")
	}
	if strings.TrimSpace(r.Advice) == "" {
		return fmt.Errorf("правило %s: пустой advice", r.ID)
	}
	switch r.Severity {
	case SeverityCritical, SeverityWarning, SeverityInfo:
	default:
		return fmt.Errorf("правило %s: недопустимая severity %q", r.ID, r.Severity)
	}
	if len(r.Source) == 0 {
		return fmt.Errorf("правило %s: нет source — отвергнуто", r.ID)
	}
	return nil
}

// NewEngine собирает движок: встроенные данные или каталог
// переопределения (rulesDir пуст → встроенные).
func NewEngine(rulesDir string) (*Engine, error) {
	if rulesDir == "" {
		t, err := loadFS(dataFS, "data")
		if err != nil {
			return nil, err
		}
		return &Engine{table: t}, nil
	}
	return NewEngineDir(rulesDir)
}

// NewEngineDir — правила и таблицы из каталога (переопределение без
// перекомпиляции). Все три файла обязательны.
func NewEngineDir(dir string) (*Engine, error) {
	fsys := os.DirFS(dir)
	t, err := loadFS(fsys, ".")
	if err != nil {
		return nil, fmt.Errorf("rules: каталог %s: %w", dir, err)
	}
	return &Engine{table: t}, nil
}

// fsPath — путь в io/fs всегда со слешами (на Windows filepath.Join
// дал бы «data\rules.json», которого во встроенной ФС нет).
func fsPath(base, name string) string {
	if base == "." || base == "" {
		return name
	}
	return base + "/" + name
}

func loadFS(fsys fs.FS, base string) (Table, error) {
	var t Table
	raw, err := fs.ReadFile(fsys, fsPath(base, "rules.json"))
	if err != nil {
		return t, fmt.Errorf("rules.json: %w", err)
	}
	if err := json.Unmarshal(raw, &struct {
		Rules *[]Rule `json:"rules"`
	}{&t.Rules}); err != nil {
		return t, fmt.Errorf("rules.json: %w", err)
	}
	if len(t.Rules) == 0 {
		return t, fmt.Errorf("rules.json: нет правил")
	}
	for _, r := range t.Rules {
		if err := validateRule(r); err != nil {
			return t, err
		}
	}
	raw, err = fs.ReadFile(fsys, fsPath(base, "network.json"))
	if err != nil {
		return t, fmt.Errorf("network.json: %w", err)
	}
	if err := json.Unmarshal(raw, &struct {
		Rules *[]Rule `json:"rules"`
	}{&t.Network}); err != nil {
		return t, fmt.Errorf("network.json: %w", err)
	}
	for _, r := range t.Network {
		if err := validateNetworkRule(r); err != nil {
			return t, err
		}
	}
	raw, err = fs.ReadFile(fsys, fsPath(base, "os_lifecycle.json"))
	if err != nil {
		return t, fmt.Errorf("os_lifecycle.json: %w", err)
	}
	if err := json.Unmarshal(raw, &struct {
		Rows *[]OSRow `json:"rows"`
	}{&t.OS}); err != nil {
		return t, fmt.Errorf("os_lifecycle.json: %w", err)
	}
	raw, err = fs.ReadFile(fsys, fsPath(base, "cpu_generations.json"))
	if err != nil {
		return t, fmt.Errorf("cpu_generations.json: %w", err)
	}
	if err := json.Unmarshal(raw, &struct {
		Rows *[]CPURow `json:"rows"`
	}{&t.CPU}); err != nil {
		return t, fmt.Errorf("cpu_generations.json: %w", err)
	}
	return t, nil
}

// SortedRules — правила в стабильном порядке (для тестов и UI).
func (e *Engine) SortedRules() []Rule {
	out := append([]Rule(nil), e.table.Rules...)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
