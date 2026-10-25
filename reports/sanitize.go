// Очистка отчёта (NR-013): IP, MAC, имена из справочника, домены,
// пути с пользователями, значения-токены заменяются стабильными
// псевдонимами. Таблица соответствий остаётся у владельца и в отчёт
// не попадает.
package reports

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// NameSource — справочник известных серверу имён (компьютеры,
// учётные записи, домены): заменяются первыми, чтобы не «съесть» их
// эвристиками.
type NameSource struct {
	Hosts    []string // имена компьютеров
	Accounts []string // учётные записи
	Domains  []string // домены
	MACs     []string
}

// Mapping — таблица соответствий псевдонимов (не покидает сервер).
type Mapping struct {
	entries []MappingEntry
	index   map[string]string
}

// MappingEntry — одна замена.
type MappingEntry struct {
	Alias string `json:"alias"`
	Kind  string `json:"kind"` // ip | mac | host | user | domain | path | secret
	Value string `json:"value"`
}

// Entries — записи таблицы (только владельческий маршрут).
func (m *Mapping) Entries() []MappingEntry {
	out := make([]MappingEntry, len(m.entries))
	copy(out, m.entries)
	return out
}

// alias — стабильный псевдоним: одно значение → один алиас.
func (m *Mapping) alias(kind, value string, prefix string) string {
	if m.index == nil {
		m.index = map[string]string{}
	}
	key := kind + "\x00" + value
	if a, ok := m.index[key]; ok {
		return a
	}
	n := 1
	for _, e := range m.entries {
		if e.Kind == kind {
			n++
		}
	}
	a := fmt.Sprintf("%s_%d", prefix, n)
	m.entries = append(m.entries, MappingEntry{Alias: a, Kind: kind, Value: value})
	m.index[key] = a
	return a
}

// Шаблоны замены.
var (
	ipv4Re = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	ipv6Re = regexp.MustCompile(`(?i)\b(?:[a-f0-9]{0,4}:){2,7}[a-f0-9]{0,4}\b`)
	macRe  = regexp.MustCompile(`\b(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}\b`)
	pathRe = regexp.MustCompile(`(?i)\\Users\\([^\\\s:|<>*?"]+)`)
	// Токены: длинные hex/base64, Bearer, PEM-блоки, пары key=value.
	hexRe        = regexp.MustCompile(`\b[a-fA-F0-9]{24,}\b`)
	base64Re     = regexp.MustCompile(`\b[A-Za-z0-9+/]{32,}={0,2}\b`)
	bearerRe     = regexp.MustCompile(`(?i)\bBearer\s+[A-Za-z0-9._+/=-]{8,}`)
	pemRe        = regexp.MustCompile(`(?s)-----BEGIN [A-Z ]+-----.*?-----END [A-Z ]+-----`)
	secretPairRe = regexp.MustCompile(`(?i)\b(password|pwd|secret|token|apikey|api_key)\s*[=:]\s*["']?[^"'\s;&]{4,}["']?`)
	domainRe     = regexp.MustCompile(`\b(?:[a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}\b`)
)

// Sanitize — очистка текста отчёта: сначала справочниковые имена
// (стабильные псевдонимы), затем эвристики. Возвращает очищенный
// текст и таблицу соответствий (владельцу).
func Sanitize(text string, names NameSource) (string, *Mapping) {
	m := &Mapping{}
	// Сортировка справочника по длине: длинные имена раньше коротких.
	sortByLen := func(list []string) []string {
		out := append([]string(nil), list...)
		sort.Slice(out, func(i, j int) bool { return len(out[i]) > len(out[j]) })
		return out
	}
	for _, host := range sortByLen(names.Hosts) {
		if host == "" {
			continue
		}
		text = strings.ReplaceAll(text, host, m.alias("host", host, "HOST"))
	}
	for _, acc := range sortByLen(names.Accounts) {
		if acc == "" {
			continue
		}
		text = strings.ReplaceAll(text, acc, m.alias("user", acc, "USER"))
	}
	for _, mac := range names.MACs {
		if mac == "" {
			continue
		}
		text = strings.ReplaceAll(text, mac, m.alias("mac", mac, "MAC"))
	}
	for _, dom := range sortByLen(names.Domains) {
		if dom == "" {
			continue
		}
		text = strings.ReplaceAll(text, dom, m.alias("domain", dom, "DOMAIN"))
	}

	// PEM раньше прочих (внутри него длинные base64).
	text = pemRe.ReplaceAllStringFunc(text, func(s string) string {
		return "[REDACTED]"
	})
	text = bearerRe.ReplaceAllStringFunc(text, func(s string) string {
		return "[REDACTED]"
	})
	text = secretPairRe.ReplaceAllStringFunc(text, func(s string) string {
		i := strings.IndexAny(s, "=:")
		return s[:i+1] + " [REDACTED]"
	})
	text = ipv6Re.ReplaceAllStringFunc(text, func(s string) string {
		// IPv6: два и более двоеточий и (буквы a-f или сжатая форма
		// "::") — иначе это похоже на время (18:52:15), не трогаем.
		if strings.Count(s, ":") < 2 {
			return s
		}
		if !strings.ContainsAny(s, "abcdefABCDEF") && !strings.Contains(s, "::") {
			return s
		}
		return m.alias("ip", strings.ToLower(s), "IP")
	})
	text = ipv4Re.ReplaceAllStringFunc(text, func(s string) string {
		return m.alias("ip", s, "IP")
	})
	text = macRe.ReplaceAllStringFunc(text, func(s string) string {
		return m.alias("mac", strings.ToLower(s), "MAC")
	})
	text = pathRe.ReplaceAllStringFunc(text, func(s string) string {
		user := pathRe.FindStringSubmatch(s)
		if len(user) < 2 {
			return s
		}
		return `\Users\` + m.alias("user", user[1], "USER")
	})
	text = base64Re.ReplaceAllStringFunc(text, func(s string) string {
		return "[REDACTED]"
	})
	text = hexRe.ReplaceAllStringFunc(text, func(s string) string {
		return "[REDACTED]"
	})
	// Домены-эвристика (после справочника): только явные FQDN-подобные.
	text = domainRe.ReplaceAllStringFunc(text, func(s string) string {
		return m.alias("domain", strings.ToLower(s), "DOMAIN")
	})
	return text, m
}

// ContainsMappingValue — защита: таблица соответствий не должна
// попасть в отчёт или ответ (тест границы).
func (m *Mapping) ContainsMappingValue(text string) bool {
	for _, e := range m.entries {
		if e.Value != "" && strings.Contains(text, e.Value) {
			return true
		}
	}
	return false
}
