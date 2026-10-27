package store

// Тесты пересчёта типов при старте и резерва шлюзов (NR-034):
// база, записанная версией до NR-032 (kind_auto пуст, шлюзов в скане
// нет), после открытия получает типы и предполагаемые связи без
// нового скана; ручные типы и SNMP-факты не трогаются.

import (
	"context"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/ShkodnikAI/NetAtlas/internal/model"
)

// nr034Scan — фикстура: сеть с роутером на шлюзе, сервером по имени,
// телефоном с mDNS-именем, случайными MAC без имён и IoT-модулем.
func nr034Scan(t *testing.T, s *Store, gateways []netip.Addr) {
	t.Helper()
	mk := func(mac, hostname, vendor, ip string, names ...string) model.Device {
		d, err := model.NewDevice(mac)
		if err != nil {
			t.Fatalf("устройство %s: %v", mac, err)
		}
		d.Hostname = hostname
		d.Vendor = vendor
		if ip != "" {
			d.IPs = []netip.Addr{netip.MustParseAddr(ip)}
		}
		seen := time.Date(2026, 10, 26, 9, 0, 0, 0, time.UTC)
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
		mk("b2:be:ad:1f:22:33", "", "", "192.168.100.30", "Android.local"),
		mk("02:00:00:00:00:10", "", "", "192.168.100.16"),
		mk("24:6f:28:00:00:01", "", "Espressif Inc.", "192.168.100.31"),
	}
	scan := ScanResult{
		Started:  time.Date(2026, 10, 26, 9, 0, 0, 0, time.UTC),
		Finished: time.Date(2026, 10, 26, 9, 4, 0, 0, time.UTC),
		Subnets:  []string{"192.168.100.0/24"},
		Devices:  devices,
		Topology: model.NewTopology(),
		Gateways: gateways,
	}
	if err := s.SaveScan(context.Background(), scan, "test"); err != nil {
		t.Fatalf("SaveScan: %v", err)
	}
}

// deviceKind — kind и kind_auto строки devices напрямую.
func deviceKind(t *testing.T, s *Store, id string) (string, string) {
	t.Helper()
	var kind, kindAuto string
	if err := s.DB().QueryRow(`SELECT kind, kind_auto FROM devices WHERE id = ?`, id).
		Scan(&kind, &kindAuto); err != nil {
		t.Fatalf("kind %s: %v", id, err)
	}
	return kind, kindAuto
}

// makeLegacyBase — имитация базы v0.1.3: типы обнулены, шлюзов в
// последнем скане нет.
func makeLegacyBase(t *testing.T, s *Store) {
	t.Helper()
	if _, err := s.DB().Exec(`UPDATE devices SET kind = 'device', kind_auto = ''`); err != nil {
		t.Fatalf("обнуление типов: %v", err)
	}
	if _, err := s.DB().Exec(`UPDATE scans SET gateways = '[]'`); err != nil {
		t.Fatalf("обнуление шлюзов: %v", err)
	}
}

// TestRecomputeKindsAtOpen — база с пустым kind_auto после старта
// получает типы: шлюз — роутер, телефон по имени, случайные MAC без
// имени — unknown, сервер по имени; всё без нового скана (NR-034 п.1).
func TestRecomputeKindsAtOpen(t *testing.T) {
	// Одна база на оба открытия: t.TempDir() при повторном вызове
	// создаёт новый каталог, поэтому путь строится один раз.
	path := filepath.Join(t.TempDir(), "netatlas.db")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("открытие: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	nr034Scan(t, s, []netip.Addr{netip.MustParseAddr("192.168.100.1")})
	makeLegacyBase(t, s)
	// Открытие заново — как обновление сервера на работающей базе.
	if err := s.Close(); err != nil {
		t.Fatalf("закрытие: %v", err)
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatalf("повторное открытие: %v", err)
	}
	t.Cleanup(func() { reopened.Close() })

	cases := map[string]string{
		"d8:0d:17:00:00:01": "router",  // адрес шлюза из резерва (.1 с устройством)
		"02:00:00:00:00:0c": "server",  // имя SERVAK
		"b2:be:ad:1f:22:33": "phone",   // Android.local — телефон по имени
		"02:00:00:00:00:10": "unknown", // случайный MAC без имени — не телефон
		"24:6f:28:00:00:01": "iot",     // Espressif
	}
	for id, want := range cases {
		got, _ := deviceKind(t, reopened, id)
		if got != want {
			t.Errorf("%s: kind %q, хочу %q", id, got, want)
		}
	}
	if _, auto := deviceKind(t, reopened, "02:00:00:00:00:10"); auto == "" {
		t.Error("kind_auto остался пустым после пересчёта")
	}
	// Карта получает предполагаемые связи без нового скана: 4 не-шлюза.
	g, err := reopened.Topology(context.Background())
	if err != nil {
		t.Fatalf("Topology: %v", err)
	}
	assumed := 0
	for _, l := range g.Links {
		if l.Source == model.LinkSourceAssumed {
			assumed++
		}
	}
	if assumed != 4 {
		t.Fatalf("предполагаемых связей %d, хочу 4", assumed)
	}
}

// TestRecomputeKeepsManualAndSwitch — ручной тип владельца и
// SNMP-факт коммутатора пересчёт не трогает (NR-034 п.1).
func TestRecomputeKeepsManualAndSwitch(t *testing.T) {
	s := openTest(t)
	nr034Scan(t, s, []netip.Addr{netip.MustParseAddr("192.168.100.1")})
	kind := "printer"
	if err := s.UpdateDevice(context.Background(), "02:00:00:00:00:0c", Update{Kind: &kind}, "test"); err != nil {
		t.Fatalf("UpdateDevice: %v", err)
	}
	// SNMP-факт: коммутатор, который классификатор не выводит.
	if _, err := s.DB().Exec(`UPDATE devices SET kind = 'switch' WHERE id = '24:6f:28:00:00:01'`); err != nil {
		t.Fatalf("switch: %v", err)
	}
	if _, err := s.RecomputeKinds(context.Background()); err != nil {
		t.Fatalf("RecomputeKinds: %v", err)
	}
	got, auto := deviceKind(t, s, "02:00:00:00:00:0c")
	if got != "printer" {
		t.Errorf("ручной тип: kind %q, хочу printer", got)
	}
	if auto != "server" {
		t.Errorf("kind_auto при ручном типе %q, хочу server (пересчитан)", auto)
	}
	got, auto = deviceKind(t, s, "24:6f:28:00:00:01")
	if got != "switch" {
		t.Errorf("SNMP-факт: kind %q, хочу switch", got)
	}
	if auto != "iot" {
		t.Errorf("kind_auto коммутатора %q, хочу iot (пересчитан)", auto)
	}
}

// TestEffectiveGatewaysFallback — резерв шлюзов (NR-034 п.1):
// скан без шлюзов — адрес берётся из первого адреса подсети, у
// которого есть устройство; без подсетей резерва нет.
func TestEffectiveGatewaysFallback(t *testing.T) {
	s := openTest(t)
	nr034Scan(t, s, nil) // скан записал gateways = []
	if got := s.effectiveGateways(context.Background()); len(got) != 1 || got[0].String() != "192.168.100.1" {
		t.Fatalf("резерв шлюзов %v, хочу [192.168.100.1]", got)
	}
	// Подсетей нет — угадывать нельзя.
	if _, err := s.DB().Exec(`UPDATE scans SET subnets = '[]'`); err != nil {
		t.Fatalf("subnets: %v", err)
	}
	if got := s.effectiveGateways(context.Background()); len(got) != 0 {
		t.Fatalf("без подсетей резерв %v, хочу пусто", got)
	}
}

// TestEffectiveGatewaysHostRoute — маршрут хоста внутри известной
// подсети попадает в резерв даже без устройства на адресе (NR-034).
func TestEffectiveGatewaysHostRoute(t *testing.T) {
	orig := gatewayProbe
	t.Cleanup(func() { gatewayProbe = orig })
	gatewayProbe = func() ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("192.168.100.254")}, nil
	}
	s := openTest(t) // открытие кэширует шлюзы хоста до первого запроса
	nr034Scan(t, s, nil)
	got := s.effectiveGateways(context.Background())
	want := map[string]bool{"192.168.100.254": true, "192.168.100.1": true}
	if len(got) != len(want) {
		t.Fatalf("резерв %v, хочу {%v}", got, want)
	}
	for _, a := range got {
		if !want[a.String()] {
			t.Fatalf("лишний адрес резерва %q", a)
		}
	}
}
