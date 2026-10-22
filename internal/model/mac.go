package model

import (
	"fmt"
	"strings"
)

// NormalizeMAC приводит MAC-адрес к каноническому виду
// aa:bb:cc:dd:ee:ff. Принимает формы AA:BB:CC:DD:EE:FF,
// aa-bb-cc-dd-ee-ff и aabb.ccdd.eeff (в любом регистре).
//
// Ошибки: неверная длина или разбивка, нешестнадцатеричные символы,
// нулевой адрес 00:00:00:00:00:00, широковещательный ff:ff:ff:ff:ff:ff
// и групповые адреса (младший бит первого октета равен 1).
func NormalizeMAC(s string) (string, error) {
	hasColon := strings.Contains(s, ":")
	hasDash := strings.Contains(s, "-")
	hasDot := strings.Contains(s, ".")
	if hasColon && hasDash {
		return "", fmt.Errorf("model: MAC %q: смешанные разделители", s)
	}

	wantGroups, wantLen := 6, 2
	var groups []string
	switch {
	case hasColon:
		groups = strings.Split(s, ":")
	case hasDash:
		groups = strings.Split(s, "-")
	case hasDot:
		groups = strings.Split(s, ".")
		wantGroups, wantLen = 3, 4
	default:
		return "", fmt.Errorf("model: MAC %q: нет разделителей", s)
	}
	if len(groups) != wantGroups {
		return "", fmt.Errorf("model: MAC %q: неверная разбивка", s)
	}

	nibbles := make([]byte, 0, wantGroups*wantLen)
	for _, g := range groups {
		if len(g) != wantLen {
			return "", fmt.Errorf("model: MAC %q: неверная длина группы", s)
		}
		for i := 0; i < len(g); i++ {
			n, ok := hexNibble(g[i])
			if !ok {
				return "", fmt.Errorf("model: MAC %q: нешестнадцатеричный символ %q", s, g[i:i+1])
			}
			nibbles = append(nibbles, n)
		}
	}

	raw := make([]byte, 6)
	for i := 0; i < 6; i++ {
		raw[i] = nibbles[2*i]<<4 | nibbles[2*i+1]
	}

	if raw[0] == 0 && raw[1] == 0 && raw[2] == 0 && raw[3] == 0 && raw[4] == 0 && raw[5] == 0 {
		return "", fmt.Errorf("model: MAC %q: нулевой адрес", s)
	}
	if raw[0] == 0xff && raw[1] == 0xff && raw[2] == 0xff && raw[3] == 0xff && raw[4] == 0xff && raw[5] == 0xff {
		return "", fmt.Errorf("model: MAC %q: широковещательный адрес", s)
	}
	if raw[0]&0x01 == 1 {
		return "", fmt.Errorf("model: MAC %q: групповой адрес", s)
	}

	return formatMAC(raw), nil
}

func hexNibble(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	default:
		return 0, false
	}
}

func formatMAC(raw []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, 17)
	for i, b := range raw {
		if i > 0 {
			out = append(out, ':')
		}
		out = append(out, digits[b>>4], digits[b&0x0f])
	}
	return string(out)
}
