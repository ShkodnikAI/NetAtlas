package store

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/ShkodnikAI/NetAtlas/internal/model"
)

// nr032Scan — скан с устройствами и шлюзом: Huawei на адресе шлюза,
// Canon-принтер, обычный ПК.
func nr032Scan(t *testing.T, withLinks bool) ScanResult {
	t.Helper()
	now := time.Date(2026, 10, 26, 10, 0, 0, 0, time.UTC)
	dev := func(mac, hostname, vendor, ip string) model.Device {
		d, err := model.NewDevice(mac)
		if err != nil {
			t.Fatalf("устройство %s: %v", mac, err)
		}
		d.Hostname = hostname
		d.Vendor = vendor
		if ip != "" {
			d.IPs = []netip.Addr{netip.MustParseAddr(ip)}
		}
		d.Observations = []model.Observation{{Source: "arp", Seen: now}}
		return d
	}
	devices := []model.Device{
		dev("d8:0d:17:00:00:01", "", "Huawei Technologies", "192.168.100.1"),
		dev("00:80:77:00:00:01", "canon-lbp", "Canon", "192.168.100.10"),
		dev("00:00:5e:00:00:01", "office-pc-01", "", "192.168.100.11"),
	}
	topo := model.NewTopology()
	if withLinks {
		topo.Links = append(topo.Links, model.Link{
			A: "00:00:5e:00:00:01", APort: "eth0",
			B: "d8:0d:17:00:00:01", BPort: "ge1",
			Source: model.LinkSourceFDB,
		})
	}
	return ScanResult{
		Started:  now.Add(-time.Minute),
		Finished: now,
		Subnets:  []string{"192.168.100.0/24"},
		Devices:  devices,
		Topology: topo,
		Gateways: []netip.Addr{netip.MustParseAddr("192.168.100.1")},
	}
}

// Классификатор (NR-032 п.1): kind_auto пишется всегда; kind = вывод
// по метаданным; шлюз получает router.
func TestSaveScanKindAuto(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	if err := s.SaveScan(ctx, nr032Scan(t, false), "test"); err != nil {
		t.Fatalf("SaveScan: %v", err)
	}
	want := map[string]string{
		"d8:0d:17:00:00:01": model.NodeKindRouter,  // шлюз
		"00:80:77:00:00:01": model.NodeKindPrinter, // Canon
		"00:00:5e:00:00:01": model.NodeKindDevice,  // ПК
	}
	for id, kind := range want {
		info, err := s.Device(ctx, id)
		if err != nil {
			t.Fatalf("устройство %s: %v", id, err)
		}
		if info.KindAuto == "" {
			t.Fatalf("%s: kind_auto пуст", id)
		}
		if info.Kind != kind {
			t.Fatalf("%s: kind = %q, хочу %q", id, info.Kind, kind)
		}
	}
}

// Ручной тип владельца (NR-032 п.1): перекрывает автоматический и
// переживает повторный скан; kind_auto продолжает обновляться.
func TestKindManualOverridesAuto(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	scan := nr032Scan(t, false)
	if err := s.SaveScan(ctx, scan, "test"); err != nil {
		t.Fatalf("SaveScan: %v", err)
	}
	const pc = "00:00:5e:00:00:01"
	manual := model.NodeKindServer
	if err := s.UpdateDevice(ctx, pc, Update{Kind: &manual}, "owner"); err != nil {
		t.Fatalf("UpdateDevice kind: %v", err)
	}
	// Повторный скан с другим выводом классификатора.
	scan.Finished = time.Now()
	scan.Devices[2].Vendor = "Canon"
	if err := s.SaveScan(ctx, scan, "test"); err != nil {
		t.Fatalf("повторный SaveScan: %v", err)
	}
	info, err := s.Device(ctx, pc)
	if err != nil {
		t.Fatalf("Device: %v", err)
	}
	if info.Kind != model.NodeKindServer {
		t.Fatalf("kind = %q, ручной тип должен был сохраниться (server)", info.Kind)
	}
	if info.KindAuto != model.NodeKindPrinter {
		t.Fatalf("kind_auto = %q, хочу printer (Canon)", info.KindAuto)
	}
	if !info.KindManual {
		t.Fatalf("kind_manual не отмечен")
	}
	// Недопустимый тип не принимается.
	bad := "fridge"
	if err := s.UpdateDevice(ctx, pc, Update{Kind: &bad}, "owner"); err == nil {
		t.Fatalf("недопустимый тип принят")
	}
}

// Предполагаемые связи (NR-032 п.3): без LLDP/FDB звезда к шлюзу
// появляется при отдаче карты и не пишется в базу; со связью FDB
// предполагаемых нет. Связь с устройством шлюза не дублируется.
func TestTopologyAssumedLinks(t *testing.T) {
	ctx := context.Background()

	// Без фактических связей: звезда.
	s := openTest(t)
	if err := s.SaveScan(ctx, nr032Scan(t, false), "test"); err != nil {
		t.Fatalf("SaveScan: %v", err)
	}
	g, err := s.Topology(ctx)
	if err != nil {
		t.Fatalf("Topology: %v", err)
	}
	assumed := 0
	for _, l := range g.Links {
		if l.Source == model.LinkSourceAssumed {
			assumed++
		}
	}
	// Три устройства, шлюз — одно из них: 2 предполагаемые связи.
	if assumed != 2 {
		t.Fatalf("предполагаемых связей %d, хочу 2", assumed)
	}
	for _, l := range g.Links {
		if l.Source != model.LinkSourceAssumed {
			t.Fatalf("неожиданная связь %+v", l)
		}
	}
	// В базе связей нет: вычисление — при отдаче.
	rows, err := s.db.QueryContext(ctx, `SELECT COUNT(*) FROM links`)
	if err != nil {
		t.Fatalf("links: %v", err)
	}
	var n int
	if !rows.Next() || rows.Scan(&n) != nil || n != 0 {
		t.Fatalf("в базе связей %d, хочу 0", n)
	}
	rows.Close()

	// Фактическая связь из FDB подавляет звезду целиком.
	s2 := openTest(t)
	if err := s2.SaveScan(ctx, nr032Scan(t, true), "test"); err != nil {
		t.Fatalf("SaveScan со связью: %v", err)
	}
	g2, err := s2.Topology(ctx)
	if err != nil {
		t.Fatalf("Topology: %v", err)
	}
	for _, l := range g2.Links {
		if l.Source == model.LinkSourceAssumed {
			t.Fatalf("предполагаемая связь при наличии FDB: %+v", l)
		}
	}
	if len(g2.Links) != 1 || g2.Links[0].Source != model.LinkSourceFDB {
		t.Fatalf("связи %+v, хочу одну fdb", g2.Links)
	}
}

// Шлюз, у которого нет своего устройства, даёт ip:-узел с kind router
// (NR-032 п.2) и звезду к устройствам.
func TestTopologyGatewayWithoutDevice(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	scan := nr032Scan(t, false)
	scan.Gateways = []netip.Addr{netip.MustParseAddr("192.168.100.254")}
	if err := s.SaveScan(ctx, scan, "test"); err != nil {
		t.Fatalf("SaveScan: %v", err)
	}
	g, err := s.Topology(ctx)
	if err != nil {
		t.Fatalf("Topology: %v", err)
	}
	var gwNode *NodeInfo
	assumed := 0
	for i := range g.Nodes {
		if g.Nodes[i].ID == "ip:192.168.100.254" {
			gwNode = &g.Nodes[i]
		}
	}
	for _, l := range g.Links {
		if l.Source == model.LinkSourceAssumed {
			assumed++
		}
	}
	if gwNode == nil {
		t.Fatalf("узел ip:192.168.100.254 не создан")
	}
	if gwNode.Kind != model.NodeKindRouter {
		t.Fatalf("kind узла шлюза = %q, хочу router", gwNode.Kind)
	}
	if assumed != 3 {
		t.Fatalf("предполагаемых связей %d, хочу 3 (все устройства)", assumed)
	}
}

// Позиции узлов (NR-032 п.4): сохранение, чтение, очистка; узел
// должен существовать, координаты — конечные числа.
func TestPositionsSaveListClear(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	if err := s.SaveScan(ctx, nr032Scan(t, false), "test"); err != nil {
		t.Fatalf("SaveScan: %v", err)
	}
	const pc = "00:00:5e:00:00:01"
	if err := s.SavePosition(ctx, pc, 120.5, -34.25, "owner"); err != nil {
		t.Fatalf("SavePosition: %v", err)
	}
	positions, err := s.Positions(ctx)
	if err != nil {
		t.Fatalf("Positions: %v", err)
	}
	if len(positions) != 1 || positions[0].ID != pc || positions[0].X != 120.5 || positions[0].Y != -34.25 {
		t.Fatalf("позиции %+v", positions)
	}
	// Повторное сохранение обновляет, а не дублирует.
	if err := s.SavePosition(ctx, pc, 10, 20, "owner"); err != nil {
		t.Fatalf("повторный SavePosition: %v", err)
	}
	if positions, _ := s.Positions(ctx); len(positions) != 1 || positions[0].X != 10 {
		t.Fatalf("позиции после обновления %+v", positions)
	}
	// Неизвестный узел и мусорные координаты отклоняются.
	if err := s.SavePosition(ctx, "manual:none", 1, 2, "owner"); err == nil {
		t.Fatalf("неизвестный узел принят")
	}
	if err := s.SavePosition(ctx, pc, nan(), 2, "owner"); err == nil {
		t.Fatalf("NaN принят")
	}
	// Очистка: список пуст.
	if err := s.ClearPositions(ctx, "owner"); err != nil {
		t.Fatalf("ClearPositions: %v", err)
	}
	if positions, _ := s.Positions(ctx); len(positions) != 0 {
		t.Fatalf("после очистки остались %+v", positions)
	}
}

func nan() float64 {
	zero := 0.0
	return zero / zero
}

// Новый тип manual-элемента и недопустимый: phone допустим (NR-032 п.5).
func TestManualKindsNR032(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	for _, kind := range []string{model.NodeKindPhone, model.NodeKindIot, model.NodeKindTV} {
		id, err := s.AddManualDevice(ctx, kind, "ручной", "owner")
		if err != nil {
			t.Fatalf("тип %q: %v", kind, err)
		}
		if !strings.HasPrefix(id, "manual:") {
			t.Fatalf("ID %q без префикса manual:", id)
		}
	}
}
