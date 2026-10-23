package scanner

import (
	"math/rand"
	"net/netip"
	"testing"
	"time"

	"github.com/ShkodnikAI/NetAtlas/internal/model"
	"github.com/ShkodnikAI/NetAtlas/scanner/dhcp"
)

var leaseNow = time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)

func leaseScope(t *testing.T) *Scope {
	t.Helper()
	s, err := NewScope([]string{"192.0.2.0/24"}, false)
	if err != nil {
		t.Fatalf("scope: %v", err)
	}
	return s
}

func devWithIP(t *testing.T, mac, ip string) model.Device {
	t.Helper()
	d, err := model.NewDevice(mac)
	if err != nil {
		t.Fatalf("устройство %q: %v", mac, err)
	}
	d.Observations = append(d.Observations, model.Observation{Source: "arp", Seen: leaseNow})
	if ip != "" {
		d.IPs = append(d.IPs, netip.MustParseAddr(ip))
	}
	return d
}

func lease(mac, ip, host, ssid string) dhcp.Lease {
	return dhcp.Lease{MAC: mac, IP: ip, Hostname: host, SSID: ssid}
}

func TestAddLeasesByMAC(t *testing.T) {
	scope := leaseScope(t)
	devices := []model.Device{devWithIP(t, "aa:bb:cc:dd:ee:f0", "192.0.2.5")}
	ls := []dhcp.Lease{lease("AA:BB:CC:DD:EE:F0", "192.0.2.6", "lab-laptop", "Office-WiFi")}
	got := AddLeases(devices, ls, scope, leaseNow)
	if len(got) != 1 {
		t.Fatalf("устройств = %d, ждём 1 (аренда по существующему MAC)", len(got))
	}
	d := got[0]
	if len(d.IPs) != 2 || d.IPs[0].String() != "192.0.2.5" || d.IPs[1].String() != "192.0.2.6" {
		t.Errorf("IPs = %v, ждём 192.0.2.5 и 192.0.2.6 по возрастанию", d.IPs)
	}
	if len(d.Names) != 1 || d.Names[0].Source != model.NameSourceDHCP || d.Names[0].Name != "lab-laptop" {
		t.Errorf("Names = %+v, ждём одно имя lab-laptop с источником dhcp", d.Names)
	}
	if !d.Names[0].Seen.Equal(leaseNow) {
		t.Errorf("имя: Seen = %v, ждём %v", d.Names[0].Seen, leaseNow)
	}
	if len(d.Observations) != 2 || d.Observations[1].Source != "dhcp" {
		t.Errorf("Observations = %+v, ждём arp + dhcp", d.Observations)
	}
	if d.SSID != "Office-WiFi" {
		t.Errorf("SSID = %q, ждём Office-WiFi", d.SSID)
	}
}

func TestAddLeasesNoDupes(t *testing.T) {
	scope := leaseScope(t)
	d := devWithIP(t, "aa:bb:cc:dd:ee:f0", "192.0.2.5")
	d.Names = append(d.Names, model.Name{Source: model.NameSourceNetBIOS, Name: "lab-laptop", Seen: leaseNow})
	devices := []model.Device{d}
	ls := []dhcp.Lease{
		lease("aa:bb:cc:dd:ee:f0", "192.0.2.5", "lab-laptop", "Office-WiFi"),
		lease("aa:bb:cc:dd:ee:f0", "192.0.2.5", "lab-laptop", ""),
	}
	got := AddLeases(devices, ls, scope, leaseNow)
	if len(got) != 1 {
		t.Fatalf("устройств = %d, ждём 1", len(got))
	}
	d = got[0]
	if len(d.IPs) != 1 {
		t.Errorf("IPs = %v, ждём без дублей (один адрес)", d.IPs)
	}
	if len(d.Names) != 1 || d.Names[0].Source != model.NameSourceNetBIOS {
		t.Errorf("Names = %+v, ждём одно имя без дубля от dhcp", d.Names)
	}
	if len(d.Observations) != 2 { // arp + один dhcp, а не по аренде
		t.Errorf("Observations = %+v, ждём arp и одно dhcp", d.Observations)
	}
	if d.SSID != "Office-WiFi" { // вторая аренда без ssid не затирает
		t.Errorf("SSID = %q, ждём сохранённый Office-WiFi", d.SSID)
	}
}

func TestAddLeasesOutsideScopeIgnored(t *testing.T) {
	scope := leaseScope(t)
	devices := []model.Device{devWithIP(t, "aa:bb:cc:dd:ee:f0", "192.0.2.5")}
	ls := []dhcp.Lease{
		lease("aa:bb:cc:dd:ee:f0", "198.51.100.9", "outsider", "Evil-WiFi"),
		lease("11:22:33:44:55:66", "198.51.100.10", "stranger", ""),
	}
	got := AddLeases(devices, ls, scope, leaseNow)
	if len(got) != 1 {
		t.Fatalf("устройств = %d, ждём 1: аренды вне scope не создают устройств", len(got))
	}
	d := got[0]
	if len(d.IPs) != 1 || d.SSID != "" || len(d.Names) != 0 || len(d.Observations) != 1 {
		t.Errorf("аренда вне scope изменила устройство: IPs=%v SSID=%q Names=%+v Obs=%+v",
			d.IPs, d.SSID, d.Names, d.Observations)
	}
}

func TestAddLeasesNewDeviceInsideScope(t *testing.T) {
	scope := leaseScope(t)
	devices := []model.Device{devWithIP(t, "aa:bb:cc:dd:ee:f0", "192.0.2.5")}
	ls := []dhcp.Lease{lease("00:00:0c:11:22:44", "192.0.2.44", "nas-box", "")}
	got := AddLeases(devices, ls, scope, leaseNow)
	if len(got) != 2 {
		t.Fatalf("устройств = %d, ждём 2 (аренда внутри scope создаёт устройство)", len(got))
	}
	d := got[1] // сортировка по первому IP: .44 после существующего .5
	if d.ID != "00:00:0c:11:22:44" || d.Class != model.ClassUnknown {
		t.Errorf("новое устройство = %+v, ждём ID 00:00:0c:11:22:44 и класс unknown", d)
	}
	if len(d.IPs) != 1 || d.IPs[0].String() != "192.0.2.44" {
		t.Errorf("IPs нового = %v, ждём 192.0.2.44", d.IPs)
	}
	if len(d.Names) != 1 || d.Names[0].Source != model.NameSourceDHCP {
		t.Errorf("Names нового = %+v, ждём dhcp-имя", d.Names)
	}
	if len(d.Observations) != 1 || d.Observations[0].Source != "dhcp" {
		t.Errorf("Observations нового = %+v, ждём одно dhcp", d.Observations)
	}
}

func TestAddLeasesNilScope(t *testing.T) {
	devices := []model.Device{devWithIP(t, "aa:bb:cc:dd:ee:f0", "192.0.2.5")}
	ls := []dhcp.Lease{
		lease("aa:bb:cc:dd:ee:f0", "192.0.2.6", "any", ""),
		lease("00:00:0c:11:22:44", "192.0.2.44", "nas", ""),
	}
	got := AddLeases(devices, ls, nil, leaseNow)
	if len(got) != 1 || len(got[0].IPs) != 1 || len(got[0].Names) != 0 {
		t.Errorf("nil-scope: результат %+v, ждём без изменений (fail-closed)", got)
	}
}

func TestAddLeasesInvalidLeasesSkipped(t *testing.T) {
	scope := leaseScope(t)
	devices := []model.Device{devWithIP(t, "aa:bb:cc:dd:ee:f0", "192.0.2.5")}
	ls := []dhcp.Lease{
		lease("не-mac", "192.0.2.7", "bad-mac", ""),
		lease("aa:bb:cc:dd:ee:f0", "не-ip", "bad-ip", ""),
		lease("aa:bb:cc:dd:ee:f0", "192.0.2.8", "bad\x01name", ""), // NewName отвергнет
		lease("00:00:00:00:00:00", "192.0.2.9", "zero-mac", ""),
	}
	got := AddLeases(devices, ls, scope, leaseNow)
	if len(got) != 1 {
		t.Fatalf("устройств = %d, ждём 1: неверные аренды не создают устройств", len(got))
	}
	d := got[0]
	if len(d.Names) != 0 {
		t.Errorf("Names = %+v, ждём пусто (управляющий символ отвергнут NewName)", d.Names)
	}
	if len(d.IPs) != 2 || d.IPs[1].String() != "192.0.2.8" {
		t.Errorf("IPs = %v, ждём добавленный 192.0.2.8 (IP валиден даже при плохом имени)", d.IPs)
	}
}

func TestAddLeasesOrderIndependent(t *testing.T) {
	scope := leaseScope(t)
	ls := []dhcp.Lease{
		lease("aa:bb:cc:dd:ee:f0", "192.0.2.6", "lab-laptop", "Office"),
		lease("00:00:0c:11:22:44", "192.0.2.44", "nas-box", ""),
		lease("28:6f:b9:00:00:02", "192.0.2.11", "print3d", "Guest"),
		lease("aa:bb:cc:dd:ee:f0", "192.0.2.5", "", ""),
	}
	base := AddLeases([]model.Device{}, ls, scope, leaseNow)
	rng := rand.New(rand.NewSource(42))
	for i := 0; i < 20; i++ {
		rng.Shuffle(len(ls), func(a, b int) { ls[a], ls[b] = ls[b], ls[a] })
		got := AddLeases([]model.Device{}, ls, scope, leaseNow)
		if len(got) != len(base) {
			t.Fatalf("перемешивание %d: устройств %d, ждём %d", i, len(got), len(base))
		}
		for j := range got {
			if got[j].ID != base[j].ID || got[j].SSID != base[j].SSID ||
				len(got[j].IPs) != len(base[j].IPs) || len(got[j].Names) != len(base[j].Names) {
				t.Fatalf("перемешивание %d: запись %d отличается: %+v против %+v", i, j, got[j], base[j])
			}
		}
	}
}

func TestFillVendors(t *testing.T) {
	devices := []model.Device{
		devWithIP(t, "00:00:0c:11:22:33", "192.0.2.10"), // Cisco в реестре
		devWithIP(t, "de:ad:be:ef:00:01", "192.0.2.11"), // неизвестный префикс
		devWithIP(t, "aa:00:04:00:00:01", "192.0.2.12"), // локально-администрируемый
	}
	got := FillVendors(devices)
	if got[0].Vendor != "Cisco Systems, Inc" {
		t.Errorf("vendor = %q, ждём Cisco Systems, Inc", got[0].Vendor)
	}
	if got[1].Vendor != "" {
		t.Errorf("vendor = %q, ждём пусто (префикса нет в реестре)", got[1].Vendor)
	}
	if got[2].Vendor != "" {
		t.Errorf("vendor = %q, ждём пусто (локально-администрируемый)", got[2].Vendor)
	}
}
