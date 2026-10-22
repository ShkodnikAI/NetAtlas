package scanner

import (
	"encoding/json"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ShkodnikAI/NetAtlas/scanner/arp"
)

func mustScope(t *testing.T, cidrs ...string) *Scope {
	t.Helper()
	s, err := NewScope(cidrs, false)
	if err != nil {
		t.Fatalf("NewScope(%v): %v", cidrs, err)
	}
	return s
}

func entry(ip, mac string) arp.Entry {
	return arp.Entry{IP: netip.MustParseAddr(ip), MAC: mac}
}

func TestFromARPMerge(t *testing.T) {
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	scope := mustScope(t, "192.168.1.0/24")
	entries := []arp.Entry{
		entry("192.168.1.30", "02:00:00:00:00:01"),
		entry("192.168.1.10", "02:00:00:00:00:02"),
		entry("192.168.1.20", "02:00:00:00:00:01"),
		entry("192.168.1.10", "02:00:00:00:00:02"), // дубликат: тот же IP и MAC
	}
	devices := FromARP(entries, scope, now)
	if len(devices) != 2 {
		t.Fatalf("получено %d устройств, хочу 2: %+v", len(devices), devices)
	}
	first := devices[0]
	if first.MAC != "02:00:00:00:00:02" {
		t.Errorf("первое устройство MAC = %q, хочу 02:00:00:00:00:02 (сортировка по первому IP)", first.MAC)
	}
	if len(first.IPs) != 1 || first.IPs[0].String() != "192.168.1.10" {
		t.Errorf("IP первого устройства = %v, хочу [192.168.1.10]", first.IPs)
	}
	if first.Class != "unknown" {
		t.Errorf("класс = %q, хочу unknown", first.Class)
	}
	if len(first.Observations) != 1 || first.Observations[0].Source != "arp" || !first.Observations[0].Seen.Equal(now) {
		t.Errorf("наблюдения = %+v, хочу одно {arp, %v}", first.Observations, now)
	}
	second := devices[1]
	if second.MAC != "02:00:00:00:00:01" || len(second.IPs) != 2 || second.IPs[0].String() != "192.168.1.20" || second.IPs[1].String() != "192.168.1.30" {
		t.Errorf("второе устройство = %+v, хочу 02:00:00:00:00:01 c IP [192.168.1.20 192.168.1.30]", second)
	}
}

func TestFromARPDropOutOfScope(t *testing.T) {
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	scope := mustScope(t, "192.168.1.0/24")
	entries := []arp.Entry{
		entry("192.168.1.10", "02:00:00:00:00:02"),
		entry("10.0.0.5", "02:00:00:00:00:03"), // вне scope
	}
	devices := FromARP(entries, scope, now)
	if len(devices) != 1 || devices[0].MAC != "02:00:00:00:00:02" {
		t.Errorf("получено %+v, хочу одно устройство 02:00:00:00:00:02", devices)
	}
}

func TestFromARPEmptyInput(t *testing.T) {
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	scope := mustScope(t, "192.168.1.0/24")
	devices := FromARP(nil, scope, now)
	if devices == nil {
		t.Fatal("результат nil, хочу пустой срез")
	}
	if len(devices) != 0 {
		t.Fatalf("получено %d устройств на пустом входе", len(devices))
	}
	b, err := json.Marshal(devices)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if strings.TrimSpace(string(b)) != "[]" {
		t.Errorf("JSON пустого входа = %s, хочу []", b)
	}
}

func TestFromARPShuffledEqual(t *testing.T) {
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	scope := mustScope(t, "192.168.1.0/24")
	base := []arp.Entry{
		entry("192.168.1.30", "02:00:00:00:00:01"),
		entry("192.168.1.10", "02:00:00:00:00:02"),
		entry("192.168.1.20", "02:00:00:00:00:01"),
		entry("192.168.1.40", "02:00:00:00:00:03"),
	}
	shuffled := []arp.Entry{
		base[3], base[1], base[2], base[0],
	}
	a := FromARP(base, scope, now)
	b := FromARP(shuffled, scope, now)
	if !reflect.DeepEqual(a, b) {
		t.Errorf("результат зависит от порядка входа:\n%+v\n%+v", a, b)
	}
}

func TestFromARPNilScopeFailClosed(t *testing.T) {
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	entries := []arp.Entry{entry("192.168.1.10", "02:00:00:00:00:02")}
	if devices := FromARP(entries, nil, now); len(devices) != 0 {
		t.Errorf("nil-Scope должен отбрасывать всё (fail closed), получено %+v", devices)
	}
}
