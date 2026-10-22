package model

import (
	"strings"
	"testing"
	"time"
)

func TestNewNameValid(t *testing.T) {
	seen := time.Date(2026, 10, 23, 10, 0, 0, 0, time.UTC)
	for _, src := range []string{NameSourceNetBIOS, NameSourceMDNS, NameSourceSSDP} {
		n, err := NewName(src, " pc-admin ", seen)
		if err != nil {
			t.Fatalf("NewName(%q): неожиданная ошибка: %v", src, err)
		}
		if n.Source != src {
			t.Errorf("Source = %q, хочу %q", n.Source, src)
		}
		if n.Name != "pc-admin" {
			t.Errorf("Name = %q, хочу %q (обрезка по краям)", n.Name, "pc-admin")
		}
		if !n.Seen.Equal(seen) {
			t.Errorf("Seen = %v, хочу %v", n.Seen, seen)
		}
	}
}

func TestNewNameInvalid(t *testing.T) {
	cases := []struct {
		name   string
		source string
		value  string
	}{
		{"пустое имя", NameSourceNetBIOS, ""},
		{"имя из пробелов", NameSourceMDNS, "   "},
		{"неизвестный источник", "dns", "pc-admin"},
		{"пустой источник", "", "pc-admin"},
		{"длиннее 255", NameSourceSSDP, strings.Repeat("a", 256)},
		{"управляющий символ", NameSourceNetBIOS, "pc\x01admin"},
		{"перевод строки", NameSourceMDNS, "pc\nadmin"},
		{"DEL", NameSourceSSDP, "pc\x7fadmin"},
	}
	for _, c := range cases {
		if _, err := NewName(c.source, c.value, time.Now()); err == nil {
			t.Errorf("%s: ожидалась ошибка, получено имя %q", c.name, c.value)
		}
	}
}

func TestNewNameMaxLengthOK(t *testing.T) {
	if _, err := NewName(NameSourceNetBIOS, strings.Repeat("a", 255), time.Now()); err != nil {
		t.Errorf("имя длиной 255 символов: неожиданная ошибка: %v", err)
	}
}

func TestNewNameMultiByteLength(t *testing.T) {
	// 128 двухбайтовых символов = 256 байт, но 128 символов — допустимо.
	long := strings.Repeat("ы", 128)
	if _, err := NewName(NameSourceMDNS, long, time.Now()); err != nil {
		t.Errorf("имя из 128 символов (256 байт): неожиданная ошибка: %v", err)
	}
}
