package model

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestNewDevice(t *testing.T) {
	d, err := NewDevice("AA-BB-CC-DD-EE-FF")
	if err != nil {
		t.Fatalf("NewDevice: неожиданная ошибка: %v", err)
	}
	if d.ID != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("ID = %q, хочу aa:bb:cc:dd:ee:ff", d.ID)
	}
	if d.MAC != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("MAC = %q, хочу aa:bb:cc:dd:ee:ff", d.MAC)
	}
	if d.Class != ClassUnknown {
		t.Errorf("Class = %q, хочу %q", d.Class, ClassUnknown)
	}
	if d.IPs == nil || len(d.IPs) != 0 {
		t.Errorf("IPs должен быть пустым срезом, не nil: %#v", d.IPs)
	}
	if d.Observations == nil || len(d.Observations) != 0 {
		t.Errorf("Observations должен быть пустым срезом, не nil: %#v", d.Observations)
	}
	if d.Names == nil || len(d.Names) != 0 {
		t.Errorf("Names должен быть пустым срезом, не nil: %#v", d.Names)
	}

	if _, err := NewDevice("01:00:5e:00:00:16"); err == nil {
		t.Error("NewDevice с групповым MAC: ожидалась ошибка")
	}
}

func TestDeviceJSONRoundTrip(t *testing.T) {
	seen := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	d, err := NewDevice("AA:BB:CC:00:11:22")
	if err != nil {
		t.Fatalf("NewDevice: %v", err)
	}
	d.IPs = append(d.IPs, netip.MustParseAddr("192.168.1.60"), netip.MustParseAddr("10.0.0.5"))
	d.Observations = append(d.Observations, Observation{Source: "arp", Seen: seen})

	b, err := json.Marshal(d)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var back Device
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if back.ID != d.ID || back.MAC != d.MAC || back.Class != d.Class || back.Hostname != d.Hostname {
		t.Errorf("round-trip изменил поля: %+v против %+v", back, d)
	}
	if len(back.IPs) != len(d.IPs) {
		t.Fatalf("round-trip изменил число IP: %d против %d", len(back.IPs), len(d.IPs))
	}
	for i := range d.IPs {
		if back.IPs[i] != d.IPs[i] {
			t.Errorf("IP[%d] = %v, хочу %v", i, back.IPs[i], d.IPs[i])
		}
	}
	if len(back.Observations) != 1 {
		t.Fatalf("round-trip изменил число наблюдений: %d", len(back.Observations))
	}
	if back.Observations[0].Source != "arp" || !back.Observations[0].Seen.Equal(seen) {
		t.Errorf("наблюдение изменилось: %+v", back.Observations[0])
	}
}

func TestDeviceJSONNoNull(t *testing.T) {
	d, err := NewDevice("02:00:00:00:00:01")
	if err != nil {
		t.Fatalf("NewDevice: %v", err)
	}
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	s := string(b)
	if strings.Contains(s, "null") {
		t.Errorf("JSON содержит null: %s", s)
	}
	if !strings.Contains(s, `"ips":[]`) {
		t.Errorf("JSON должен содержать ips: [], получил: %s", s)
	}
	if !strings.Contains(s, `"observations":[]`) {
		t.Errorf("JSON должен содержать observations: [], получил: %s", s)
	}
	if !strings.Contains(s, `"names":[]`) {
		t.Errorf("JSON должен содержать names: [], получил: %s", s)
	}
}
