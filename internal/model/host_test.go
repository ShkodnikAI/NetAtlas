package model

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestNewHost(t *testing.T) {
	ip := netip.MustParseAddr("192.168.1.50")
	h, err := NewHost(ip)
	if err != nil {
		t.Fatalf("NewHost: неожиданная ошибка: %v", err)
	}
	if h.IP != ip {
		t.Errorf("IP = %v, хочу %v", h.IP, ip)
	}
	if h.Names == nil || len(h.Names) != 0 {
		t.Errorf("Names должен быть пустым срезом, не nil: %#v", h.Names)
	}
	if h.Observations == nil || len(h.Observations) != 0 {
		t.Errorf("Observations должен быть пустым срезом, не nil: %#v", h.Observations)
	}
	if h.RTT != 0 {
		t.Errorf("RTT = %v, хочу ноль", h.RTT)
	}
}

func TestNewHostInvalid(t *testing.T) {
	cases := []struct {
		name string
		ip   netip.Addr
	}{
		{"невалидный", netip.Addr{}},
		{"IPv6", netip.MustParseAddr("fe80::1")},
		{"IPv4-в-IPv6", netip.MustParseAddr("::ffff:192.168.1.50")},
	}
	for _, c := range cases {
		if _, err := NewHost(c.ip); err == nil {
			t.Errorf("%s: ожидалась ошибка", c.name)
		}
	}
}

func TestHostJSONRoundTrip(t *testing.T) {
	seen := time.Date(2026, 10, 23, 11, 0, 0, 0, time.UTC)
	ip := netip.MustParseAddr("10.0.0.99")
	h, err := NewHost(ip)
	if err != nil {
		t.Fatalf("NewHost: %v", err)
	}
	name, err := NewName(NameSourceMDNS, "printer.local", seen)
	if err != nil {
		t.Fatalf("NewName: %v", err)
	}
	h.Names = append(h.Names, name)
	h.RTT = 1500
	h.Observations = append(h.Observations, Observation{Source: "ping", Seen: seen})

	b, err := json.Marshal(h)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var back Host
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if back.IP != h.IP {
		t.Errorf("IP = %v, хочу %v", back.IP, h.IP)
	}
	if back.RTT != h.RTT {
		t.Errorf("RTT = %v, хочу %v", back.RTT, h.RTT)
	}
	if len(back.Names) != 1 || back.Names[0].Source != NameSourceMDNS || back.Names[0].Name != "printer.local" {
		t.Errorf("имена изменились: %+v", back.Names)
	}
	if len(back.Observations) != 1 || back.Observations[0].Source != "ping" {
		t.Errorf("наблюдения изменились: %+v", back.Observations)
	}
}

func TestHostJSONNoNull(t *testing.T) {
	h, err := NewHost(netip.MustParseAddr("10.0.0.98"))
	if err != nil {
		t.Fatalf("NewHost: %v", err)
	}
	b, err := json.Marshal(h)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	s := string(b)
	if strings.Contains(s, "null") {
		t.Errorf("JSON содержит null: %s", s)
	}
	if !strings.Contains(s, `"names":[]`) {
		t.Errorf("JSON должен содержать names: [], получил: %s", s)
	}
	if !strings.Contains(s, `"observations":[]`) {
		t.Errorf("JSON должен содержать observations: [], получил: %s", s)
	}
}
