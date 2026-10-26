// Command seed — фикстура сквозных тестов интерфейса (NR-031, NR-032):
// открывает базу SQLite, накатывает миграции и заполняет её
// подставными данными сканирования. Сеть NR-032 (п.6): роутер Huawei
// на адресе шлюза, принтер Canon, телефон со случайным MAC и именем
// Android.local, сервер, два компьютера, IoT-модуль; связей
// LLDP/FDB нет — карта рисует предполагаемые связи «устройство —
// шлюз» и раскладывает узлы сеткой. Данные детерминированы.
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
		names                     []struct{ source, value string }
	}
	specs := []spec{
		// Шлюз: Huawei на адресе маршрутизатора по умолчанию.
		{"d8:0d:17:00:00:01", "", "Huawei Technologies", "192.168.100.1", []string{"arp", "ping"}, nil},
		// Сервер и два компьютера.
		{"02:00:00:00:00:0c", "SERVAK", "Giga-Byte Technology", "192.168.100.12", []string{"arp", "ping"}, nil},
		{"02:00:00:00:00:0a", "office-pc-01", "", "192.168.100.10", []string{"arp", "ping"}, nil},
		{"02:00:00:00:00:0b", "office-pc-02", "", "192.168.100.11", []string{"ping"}, nil},
		// Принтер Canon.
		{"00:80:77:00:00:01", "", "Canon", "192.168.100.20", []string{"arp"}, []struct{ source, value string }{{model.NameSourceNetBIOS, "canon-lbp-1 этаж"}}},
		// Телефон со случайным MAC (бит U/L) и mDNS-именем.
		{"b2:be:ad:1f:22:33", "", "", "192.168.100.30", []string{"arp", "ping"}, []struct{ source, value string }{{model.NameSourceMDNS, "Android.local"}}},
		// IoT-модуль.
		{"24:6f:28:00:00:01", "", "Espressif Inc.", "192.168.100.31", []string{"arp"}, nil},
		// Прочие: подписи, таблица устройств.
		{"02:00:00:00:00:0f", "", "Raspberry Pi Trading Ltd", "192.168.100.15", []string{"arp"}, nil},
		{"02:00:00:00:00:10", "", "", "192.168.100.16", []string{"arp", "ping"}, nil},
		{"02:00:00:00:00:11", "", "", "192.168.100.17", []string{"ping"}, nil},
		{"02:00:00:00:00:12", "", "", "192.168.100.18", []string{"arp"}, nil},
		{"02:00:00:00:00:13", "", "", "", []string{"arp"}, nil},
	}
	devices := make([]model.Device, 0, len(specs))
	for i, s := range specs {
		d, err := device(s.mac, s.hostname, s.vendor, s.ip, s.sources...)
		if err != nil {
			return fmt.Errorf("устройство %d: %w", i, err)
		}
		for _, nm := range s.names {
			if err := name(&d, nm.source, nm.value); err != nil {
				return fmt.Errorf("имя устройства %d: %w", i, err)
			}
		}
		devices = append(devices, d)
	}

	// Связей LLDP/FDB нет (SNMP-коммутатора в сети нет): карта строит
	// предполагаемые связи «устройство — шлюз» (NR-032 п.3).
	topology := model.NewTopology()

	scan := store.ScanResult{
		Started:  time.Date(2026, 10, 26, 9, 0, 0, 0, time.UTC),
		Finished: time.Date(2026, 10, 26, 9, 4, 0, 0, time.UTC),
		Subnets:  []string{"192.168.100.0/24"},
		Devices:  devices,
		Topology: topology,
		Gateways: []netip.Addr{netip.MustParseAddr("192.168.100.1")},
	}
	if err := st.SaveScan(context.Background(), scan, "e2e"); err != nil {
		return fmt.Errorf("SaveScan: %w", err)
	}
	fmt.Println("seed: 12 устройств, шлюз 192.168.100.1, связей нет (карта построит предполагаемые)")
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "seed: %v\n", err)
		os.Exit(1)
	}
}
