package store

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/ShkodnikAI/NetAtlas/internal/model"
)

// nr037Scan — база NR-037: шлюз Huawei по адресу .1 без имён,
// сервер с hostname, телефон с mDNS-именем. Шлюз задан явно
// (scans.gateways), как у владельца.
func nr037Scan(t *testing.T, s *Store) {
	t.Helper()
	mk := func(mac, hostname, vendor, ip string, names ...string) model.Device {
		d, err := model.NewDevice(mac)
		if err != nil {
			t.Fatalf("фикстура %s: %v", mac, err)
		}
		d.Hostname = hostname
		d.Vendor = vendor
		if ip != "" {
			d.IPs = []netip.Addr{netip.MustParseAddr(ip)}
		}
		seen := time.Date(2026, 10, 29, 9, 0, 0, 0, time.UTC)
		d.Observations = append(d.Observations, model.Observation{Source: "arp", Seen: seen})
		for _, n := range names {
			name, err := model.NewName(model.NameSourceMDNS, n, seen)
			if err != nil {
				t.Fatalf("имя %s: %v", n, err)
			}
			d.Names = append(d.Names, name)
		}
		return d
	}
	devices := []model.Device{
		mk("d8:0d:17:00:00:01", "", "Huawei Technologies", "192.168.100.1"),
		mk("02:00:00:00:00:0c", "SERVAK", "Giga-Byte Technology", "192.168.100.12"),
		mk("02:00:00:00:00:30", "", "", "192.168.100.30", "printer.local"),
	}
	scan := ScanResult{
		Started:  time.Date(2026, 10, 29, 9, 0, 0, 0, time.UTC),
		Finished: time.Date(2026, 10, 29, 9, 4, 0, 0, time.UTC),
		Subnets:  []string{"192.168.100.0/24"},
		Devices:  devices,
		Topology: model.NewTopology(),
		Gateways: []netip.Addr{netip.MustParseAddr("192.168.100.1")},
	}
	if err := s.SaveScan(context.Background(), scan, "test"); err != nil {
		t.Fatalf("SaveScan: %v", err)
	}
}

// NR-037 п.3: шлюз без имени называется «Роутер <IP>» — то же правило,
// что в таблице устройств и карточке. Имя (hostname или найденное)
// сильнее адреса; не-шлюзам правило не достаётся.
func TestTopologyGatewayLabel(t *testing.T) {
	s := openTest(t)
	nr037Scan(t, s)

	g, err := s.Topology(context.Background())
	if err != nil {
		t.Fatalf("Topology: %v", err)
	}
	labels := map[string]string{}
	for _, n := range g.Nodes {
		labels[n.ID] = n.Label
	}
	if got := labels["d8:0d:17:00:00:01"]; got != "Роутер 192.168.100.1" {
		t.Fatalf("подпись шлюза: %q, хочу %q", got, "Роутер 192.168.100.1")
	}
	if got := labels["02:00:00:00:00:0c"]; got != "SERVAK" {
		t.Fatalf("подпись с hostname: %q, хочу SERVAK", got)
	}
	if got := labels["02:00:00:00:00:30"]; got != "printer.local" {
		t.Fatalf("подпись с найденным именем: %q, хочу printer.local", got)
	}
}

// nodeLabel напрямую: порядок «имя → hostname → найденное имя →
// Роутер <IP> → производитель + хвост MAC → идентификатор».
func TestNodeLabelGatewayRule(t *testing.T) {
	cases := []struct {
		name     string
		id       string
		label    string
		hostname string
		first    string
		vendor   string
		gw       string
		want     string
	}{
		{"шлюз без имён", "d8:0d:17:00:00:01", "", "", "", "Huawei Technologies", "192.168.100.1", "Роутер 192.168.100.1"},
		{"шлюз с hostname", "d8:0d:17:00:00:01", "", "home-gw", "", "Huawei", "192.168.100.1", "home-gw"},
		{"имя сильнее всего", "02:00:00:00:00:01", "мой-роутер", "", "", "", "10.0.0.1", "мой-роутер"},
		{"не шлюз — производитель", "02:00:00:00:00:aa", "", "", "", "TP-Link", "", "TP-Link 00:00:aa"},
		{"ip-узел шлюза", "ip:192.168.100.1", "", "", "", "", "", "ip:192.168.100.1"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := nodeLabel(c.id, c.label, c.hostname, c.first, c.vendor, c.gw)
			if got != c.want {
				t.Fatalf("nodeLabel: %q, хочу %q", got, c.want)
			}
		})
	}
}

// NR-037 п.3: список устройств несёт kind — таблица называет шлюз
// «Роутер <IP>» тем же правилом, что и карта.
func TestListDevicesFillsKind(t *testing.T) {
	s := openTest(t)
	nr037Scan(t, s)

	devs, err := s.ListDevices(context.Background())
	if err != nil {
		t.Fatalf("ListDevices: %v", err)
	}
	kinds := map[string]string{}
	for _, d := range devs {
		kinds[d.ID] = d.Kind
	}
	if got := kinds["d8:0d:17:00:00:01"]; got != "router" {
		t.Fatalf("kind шлюза: %q, хочу router", got)
	}
	if got := kinds["02:00:00:00:00:0c"]; got != "server" {
		t.Fatalf("kind сервера: %q, хочу server", got)
	}
}
