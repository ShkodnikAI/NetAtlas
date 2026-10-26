// Command seed — фикстура сквозных тестов интерфейса (NR-031):
// открывает базу SQLite, накатывает миграции и заполняет её
// подставными данными сканирования. Запускается до старта сервера;
// данные детерминированы: 12 устройств с длинными MAC, из них 4
// связаны через коммутатор, остальные без связей (сетка на карте).
//
// Использование: seed <путь-к-базе>
package main

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"time"

	"github.com/ShkodnikAI/NetAtlas/internal/model"
	"github.com/ShkodnikAI/NetAtlas/server/store"
)

func device(mac, hostname, vendor, ip string, sources ...string) (model.Device, error) {
	d, err := model.NewDevice(mac)
	if err != nil {
		return model.Device{}, err
	}
	d.Hostname = hostname
	d.Vendor = vendor
	if ip != "" {
		d.IPs = []netip.Addr{netip.MustParseAddr(ip)}
	}
	seen := time.Date(2026, 10, 26, 9, 0, 0, 0, time.UTC)
	for _, s := range sources {
		d.Observations = append(d.Observations, model.Observation{Source: s, Seen: seen})
	}
	return d, nil
}

func name(d *model.Device, source, value string) error {
	n, err := model.NewName(source, value, time.Date(2026, 10, 26, 8, 30, 0, 0, time.UTC))
	if err != nil {
		return err
	}
	d.Names = append(d.Names, n)
	return nil
}

func run() error {
	if len(os.Args) != 2 {
		return fmt.Errorf("использование: seed <путь-к-базе>")
	}
	st, err := store.Open(os.Args[1])
	if err != nil {
		return fmt.Errorf("хранилище: %w", err)
	}
	defer st.Close()

	type spec struct {
		mac, hostname, vendor, ip string
		sources                   []string
	}
	specs := []spec{
		{"02:00:00:00:00:0a", "office-pc-01", "", "192.168.100.10", []string{"arp", "ping"}},
		{"02:00:00:00:00:0b", "office-pc-02", "", "192.168.100.11", []string{"ping"}},
		{"02:00:00:00:00:0c", "nas-server", "", "192.168.100.12", []string{"arp", "ping", "snmp"}},
		{"02:00:00:00:00:0d", "", "TP-Link Technologies", "192.168.100.13", []string{"arp"}},
		{"02:00:00:00:00:0e", "", "Espressif Inc.", "192.168.100.14", []string{"arp", "ping"}},
		{"02:00:00:00:00:0f", "", "Raspberry Pi Trading Ltd", "192.168.100.15", []string{"arp"}},
		{"02:00:00:00:00:10", "", "", "192.168.100.16", []string{"arp", "ping"}},
		{"02:00:00:00:00:11", "", "", "192.168.100.17", []string{"ping"}},
		{"02:00:00:00:00:12", "", "", "192.168.100.18", []string{"arp"}},
		{"02:00:00:00:00:13", "", "", "", []string{"arp"}},
		{"02:00:00:00:00:14", "", "", "", []string{"ping"}},
		{"02:00:00:00:00:15", "", "", "", nil},
	}
	devices := make([]model.Device, 0, len(specs))
	for i, s := range specs {
		d, err := device(s.mac, s.hostname, s.vendor, s.ip, s.sources...)
		if err != nil {
			return fmt.Errorf("устройство %d: %w", i, err)
		}
		// Имена у двух устройств: подпись на карте берётся из них.
		if s.mac == "02:00:00:00:00:10" {
			if err := name(&d, model.NameSourceNetBIOS, "printer-hp-1 этаж"); err != nil {
				return fmt.Errorf("имя printer: %w", err)
			}
		}
		if s.mac == "02:00:00:00:00:11" {
			if err := name(&d, model.NameSourceMDNS, "cam-lobby.local"); err != nil {
				return fmt.Errorf("имя камеры: %w", err)
			}
		}
		devices = append(devices, d)
	}

	sw := netip.MustParseAddr("192.168.100.1")
	topology := model.NewTopology()
	topology.Links = []model.Link{
		{A: "02:00:00:00:00:0a", APort: "eth0", B: "02:00:00:00:00:0b", BPort: "eth0", Source: "fdb"},
		{A: "02:00:00:00:00:0a", APort: "eth0", B: "ip:" + sw.String(), BPort: "ge1", Source: "lldp"},
		{A: "02:00:00:00:00:0b", APort: "eth0", B: "ip:" + sw.String(), BPort: "ge2", Source: "fdb"},
	}

	scan := store.ScanResult{
		Started:  time.Date(2026, 10, 26, 9, 0, 0, 0, time.UTC),
		Finished: time.Date(2026, 10, 26, 9, 4, 0, 0, time.UTC),
		Subnets:  []string{"192.168.100.0/24"},
		Devices:  devices,
		Topology: topology,
	}
	if err := st.SaveScan(context.Background(), scan, "e2e"); err != nil {
		return fmt.Errorf("SaveScan: %w", err)
	}
	fmt.Println("seed: 12 устройств, 3 связи записаны")
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "seed: %v\n", err)
		os.Exit(1)
	}
}
