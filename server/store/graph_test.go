package store

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/ShkodnikAI/NetAtlas/internal/model"
)

// NR-030 п.1: ListDevices возвращает устройства с адресами, именами
// и наблюдениями; пустые срезы остаются пустыми ([]), не nil.
func TestListDevicesFillsSlices(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	now := time.Now()

	full, err := model.NewDevice("02:00:00:00:00:01")
	if err != nil {
		t.Fatalf("фикстура: %v", err)
	}
	full.IPs = []netip.Addr{netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("10.0.0.1")}
	n1, err := model.NewName(model.NameSourceNetBIOS, "alpha", now.Add(-2*time.Hour))
	if err != nil {
		t.Fatalf("имя 1: %v", err)
	}
	n2, err := model.NewName(model.NameSourceMDNS, "beta.local", now.Add(-time.Hour))
	if err != nil {
		t.Fatalf("имя 2: %v", err)
	}
	full.Names = []model.Name{n1, n2}
	full.Observations = []model.Observation{
		{Source: "arp", Seen: now},
		{Source: "ping", Seen: now},
		{Source: "dhcp", Seen: now},
	}

	bare, err := model.NewDevice("02:00:00:00:00:02")
	if err != nil {
		t.Fatalf("фикстура: %v", err)
	}
	bare.IPs = []netip.Addr{netip.MustParseAddr("10.0.0.3")}

	scan := ScanResult{
		Started:  now.Add(-time.Minute),
		Finished: now,
		Subnets:  []string{"10.0.0.0/24"},
		Devices:  []model.Device{full, bare},
		Topology: model.NewTopology(),
	}
	if err := s.SaveScan(ctx, scan, "owner"); err != nil {
		t.Fatalf("SaveScan: %v", err)
	}

	devs, err := s.ListDevices(ctx)
	if err != nil {
		t.Fatalf("ListDevices: %v", err)
	}
	if len(devs) != 2 {
		t.Fatalf("устройств %d, хочу 2", len(devs))
	}
	// Порядок списка — по id.
	if devs[0].ID != "02:00:00:00:00:01" || devs[1].ID != "02:00:00:00:00:02" {
		t.Fatalf("порядок: %s, %s", devs[0].ID, devs[1].ID)
	}

	// Полное устройство: два адреса по возрастанию, два имени по
	// времени, три наблюдения.
	d := devs[0]
	if len(d.IPs) != 2 || d.IPs[0].String() != "10.0.0.1" || d.IPs[1].String() != "10.0.0.2" {
		t.Fatalf("адреса: %v, хочу 10.0.0.1, 10.0.0.2", d.IPs)
	}
	if len(d.Names) != 2 || d.Names[0].Name != "alpha" || d.Names[1].Name != "beta.local" {
		t.Fatalf("имена: %+v, хочу alpha, beta.local", d.Names)
	}
	if len(d.Observations) != 3 {
		t.Fatalf("наблюдений %d (%+v), хочу 3", len(d.Observations), d.Observations)
	}
	sources := map[string]bool{}
	for _, o := range d.Observations {
		sources[o.Source] = true
	}
	if !sources["arp"] || !sources["ping"] || !sources["dhcp"] {
		t.Fatalf("источники наблюдений: %+v", sources)
	}

	// Скудное устройство: адрес есть, имена и наблюдения пустые ([]).
	b := devs[1]
	if len(b.IPs) != 1 || b.IPs[0].String() != "10.0.0.3" {
		t.Fatalf("адреса: %v, хочу [10.0.0.3]", b.IPs)
	}
	if b.Names == nil || len(b.Names) != 0 {
		t.Fatalf("имена: %#v, хочу пустой срез, не nil", b.Names)
	}
	if b.Observations == nil || len(b.Observations) != 0 {
		t.Fatalf("наблюдения: %#v, хочу пустой срез, не nil", b.Observations)
	}

	// ListDevicesByClass наследует заполнение (фильтр по классу).
	unknown, err := s.ListDevicesByClass(ctx, model.ClassUnknown)
	if err != nil {
		t.Fatalf("ListDevicesByClass: %v", err)
	}
	if len(unknown) != 2 || len(unknown[0].Names) != 2 || len(unknown[0].Observations) != 3 {
		t.Fatalf("фильтр по классу потерял данные: %+v", unknown)
	}
}

// NR-031 п.4: подпись узла без имён — «производитель + последние 3
// байта MAC»; без производителя — голый MAC.
func TestTopologyLabelVendorFallback(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	now := time.Now()

	vendored, err := model.NewDevice("02:00:00:00:00:aa")
	if err != nil {
		t.Fatalf("фикстура: %v", err)
	}
	vendored.Vendor = "TP-Link"
	vendored.IPs = []netip.Addr{netip.MustParseAddr("10.0.0.9")}

	bare, err := model.NewDevice("02:00:00:00:00:bb")
	if err != nil {
		t.Fatalf("фикстура: %v", err)
	}

	scan := ScanResult{
		Started:  now.Add(-time.Minute),
		Finished: now,
		Subnets:  []string{"10.0.0.0/24"},
		Devices:  []model.Device{vendored, bare},
		Topology: model.NewTopology(),
	}
	if err := s.SaveScan(ctx, scan, "owner"); err != nil {
		t.Fatalf("SaveScan: %v", err)
	}

	g, err := s.Topology(ctx)
	if err != nil {
		t.Fatalf("Topology: %v", err)
	}
	labels := map[string]string{}
	for _, n := range g.Nodes {
		labels[n.ID] = n.Label
	}
	if got := labels["02:00:00:00:00:aa"]; got != "TP-Link 00:00:aa" {
		t.Fatalf("подпись с производителем: %q, хочу %q", got, "TP-Link 00:00:aa")
	}
	if got := labels["02:00:00:00:00:bb"]; got != "02:00:00:00:00:bb" {
		t.Fatalf("подпись без производителя: %q, хочу голый MAC", got)
	}
}
