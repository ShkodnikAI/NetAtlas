package scanner

import (
	"net/netip"
	"testing"
)

func TestNewScopeAndContains(t *testing.T) {
	s, err := NewScope([]string{"10.0.0.0/24"}, false)
	if err != nil {
		t.Fatalf("NewScope: неожиданная ошибка: %v", err)
	}
	if !s.Contains(netip.MustParseAddr("10.0.0.5")) {
		t.Error("10.0.0.5 должен быть внутри 10.0.0.0/24")
	}
	if s.Contains(netip.MustParseAddr("10.0.1.5")) {
		t.Error("10.0.1.5 не должен быть внутри 10.0.0.0/24")
	}
	if s.Contains(netip.Addr{}) {
		t.Error("невалидный адрес не должен быть внутри")
	}
	if s.Contains(netip.MustParseAddr("::1")) {
		t.Error("IPv6-адрес не должен быть внутри IPv4-границ")
	}

	// Две подсети: попадание в любую.
	s2, err := NewScope([]string{"10.0.0.0/24", "192.168.1.0/24"}, false)
	if err != nil {
		t.Fatalf("NewScope: %v", err)
	}
	if !s2.Contains(netip.MustParseAddr("192.168.1.7")) {
		t.Error("192.168.1.7 должен быть внутри второй подсети")
	}
}

func TestNewScopeErrors(t *testing.T) {
	tests := []struct {
		name       string
		cidrs      []string
		allowLarge bool
	}{
		{name: "пустой список", cidrs: nil},
		{name: "пустой список явный", cidrs: []string{}},
		{name: "неверный CIDR", cidrs: []string{"foo"}},
		{name: "IPv6", cidrs: []string{"::1"}},
		{name: "IPv6-сеть", cidrs: []string{"fe80::/10"}},
		{name: "loopback", cidrs: []string{"127.0.0.0/8"}},
		{name: "loopback узкая", cidrs: []string{"127.0.0.0/24"}},
		{name: "групповые", cidrs: []string{"224.0.0.0/4"}},
		{name: "групповые узкая", cidrs: []string{"230.0.0.0/8"}},
		{name: "эта сеть", cidrs: []string{"0.0.0.0/8"}},
		{name: "link-local", cidrs: []string{"169.254.0.0/16"}},
		{name: "шире /22 без allowLarge", cidrs: []string{"10.0.0.0/16"}},
		{name: "шире /22 в списке", cidrs: []string{"10.0.0.0/24", "10.1.0.0/21"}},
	}
	for _, tt := range tests {
		if _, err := NewScope(tt.cidrs, tt.allowLarge); err == nil {
			t.Errorf("%s: ожидалась ошибка", tt.name)
		}
	}
}

func TestNewScopeAllowLarge(t *testing.T) {
	if _, err := NewScope([]string{"10.0.0.0/16"}, true); err != nil {
		t.Errorf("10.0.0.0/16 с allowLarge: неожиданная ошибка: %v", err)
	}
	if _, err := NewScope([]string{"10.0.0.0/22"}, false); err != nil {
		t.Errorf("10.0.0.0/22 (1024 адреса) без allowLarge допустима: %v", err)
	}
}
