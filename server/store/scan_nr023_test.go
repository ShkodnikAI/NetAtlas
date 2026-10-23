// Тесты хостов без MAC в хранилище (NR-023): сохранение ip:-записей,
// дедупликация при появлении MAC, сохранение ручного класса.

package store

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/ShkodnikAI/NetAtlas/internal/model"
)

// hostFix — хост без MAC с именем и наблюдением ping.
func hostFix(t *testing.T, ip, name string, now time.Time) model.Host {
	t.Helper()
	h, err := model.NewHost(netip.MustParseAddr(ip))
	if err != nil {
		t.Fatalf("хост %s: %v", ip, err)
	}
	if name != "" {
		n, err := model.NewName(model.NameSourceSSDP, name, now)
		if err != nil {
			t.Fatalf("имя хоста: %v", err)
		}
		h.Names = append(h.Names, n)
	}
	h.Observations = append(h.Observations, model.Observation{Source: "ping", Seen: now})
	return h
}

// ipHostCount — число строк devices с данным ip:-идентификатором.
func ipHostCount(t *testing.T, s *Store, ip string) int {
	t.Helper()
	var n int
	if err := s.DB().QueryRow(`SELECT COUNT(*) FROM devices WHERE id = ?`,
		"ip:"+ip).Scan(&n); err != nil {
		t.Fatalf("подсчёт ip:%s: %v", ip, err)
	}
	return n
}

// ip-хост сохраняется как устройство kind=host, класс unknown, с
// наблюдением ping и именем; оповещение «новое неизвестное» создаётся.
func TestSaveScanIPHostSaved(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	now := time.Now()

	scan := ScanResult{
		Started:  now.Add(-time.Minute),
		Finished: now,
		Subnets:  []string{"10.0.0.0/24"},
		Hosts:    []model.Host{hostFix(t, "10.0.0.9", "printer-lab", now)},
		Topology: model.NewTopology(),
	}
	if err := s.SaveScan(ctx, scan, "owner"); err != nil {
		t.Fatalf("SaveScan: %v", err)
	}

	if got := ipHostCount(t, s, "10.0.0.9"); got != 1 {
		t.Fatalf("ip-хост не сохранён: строк %d", got)
	}
	var kind, class string
	var manual int
	if err := s.DB().QueryRow(
		`SELECT kind, class, manual FROM devices WHERE id = 'ip:10.0.0.9'`,
	).Scan(&kind, &class, &manual); err != nil {
		t.Fatalf("чтение ip-хоста: %v", err)
	}
	if kind != "host" || class != "unknown" || manual != 0 {
		t.Fatalf("kind/class/manual = %s/%s/%d, хочу host/unknown/0", kind, class, manual)
	}
	var source string
	if err := s.DB().QueryRow(
		`SELECT source FROM observations WHERE device_id = 'ip:10.0.0.9'`,
	).Scan(&source); err != nil {
		t.Fatalf("наблюдение: %v", err)
	}
	if source != "ping" {
		t.Fatalf("наблюдение %q, хочу ping", source)
	}
	var name string
	if err := s.DB().QueryRow(
		`SELECT name FROM device_names WHERE device_id = 'ip:10.0.0.9'`,
	).Scan(&name); err != nil {
		t.Fatalf("имя: %v", err)
	}
	if name != "printer-lab" {
		t.Fatalf("имя %q, хочу printer-lab", name)
	}
	var alerts int
	if err := s.DB().QueryRow(
		`SELECT COUNT(*) FROM alerts WHERE device_id = 'ip:10.0.0.9' AND closed = ''`,
	).Scan(&alerts); err != nil {
		t.Fatalf("оповещения: %v", err)
	}
	if alerts != 1 {
		t.Fatalf("открытых оповещений %d, хочу 1", alerts)
	}
	// Адрес ip-хоста не пишется в device_ips (ID уже несёт адрес).
	var ips int
	if err := s.DB().QueryRow(
		`SELECT COUNT(*) FROM device_ips WHERE ip = '10.0.0.9'`,
	).Scan(&ips); err != nil {
		t.Fatalf("device_ips: %v", err)
	}
	if ips != 0 {
		t.Fatalf("строк в device_ips %d, хочу 0", ips)
	}
}

// Повторное появление адреса с MAC: ip-запись удаляется как найденная,
// дубли нет; удаление в аудите той же транзакции.
func TestSaveScanIPHostDedupOnMAC(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	now := time.Now()

	first := ScanResult{
		Started:  now.Add(-time.Minute),
		Finished: now,
		Subnets:  []string{"10.0.0.0/24"},
		Hosts:    []model.Host{hostFix(t, "10.0.0.9", "ghost", now)},
		Topology: model.NewTopology(),
	}
	if err := s.SaveScan(ctx, first, "owner"); err != nil {
		t.Fatalf("первый скан: %v", err)
	}

	second := scanFix(t, now.Add(time.Hour), "02:00:00:00:00:09", "10.0.0.9", "found")
	if err := s.SaveScan(ctx, second, "owner"); err != nil {
		t.Fatalf("второй скан: %v", err)
	}

	if got := ipHostCount(t, s, "10.0.0.9"); got != 0 {
		t.Fatalf("ip-запись осталась: строк %d", got)
	}
	var macs int
	if err := s.DB().QueryRow(
		`SELECT COUNT(*) FROM devices WHERE id = '02:00:00:00:00:09'`,
	).Scan(&macs); err != nil {
		t.Fatalf("устройство: %v", err)
	}
	if macs != 1 {
		t.Fatalf("устройств с MAC %d, хочу 1", macs)
	}
	var drops int
	if err := s.DB().QueryRow(
		`SELECT COUNT(*) FROM audit_log WHERE action = 'drop_ip_host'`,
	).Scan(&drops); err != nil {
		t.Fatalf("аудит: %v", err)
	}
	if drops != 1 {
		t.Fatalf("записей drop_ip_host %d, хочу 1", drops)
	}
	// Оповещение ip-записи закрыто вместе с ней, у нового устройства — своё.
	var stale int
	if err := s.DB().QueryRow(
		`SELECT COUNT(*) FROM alerts WHERE device_id = 'ip:10.0.0.9'`,
	).Scan(&stale); err != nil {
		t.Fatalf("оповещения ip: %v", err)
	}
	if stale != 0 {
		t.Fatalf("осиротевших оповещений %d, хочу 0", stale)
	}
	var fresh int
	if err := s.DB().QueryRow(
		`SELECT COUNT(*) FROM alerts WHERE device_id = '02:00:00:00:00:09' AND closed = ''`,
	).Scan(&fresh); err != nil {
		t.Fatalf("оповещение нового: %v", err)
	}
	if fresh != 1 {
		t.Fatalf("открытых оповещений нового устройства %d, хочу 1", fresh)
	}
}

// Устройство с этим адресом уже в базе (из прошлого скана, в этот не
// попало): ip-дубль не создаётся.
func TestSaveScanIPHostSkipsKnownIP(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	now := time.Now()

	first := scanFix(t, now, "02:00:00:00:00:09", "10.0.0.9", "found")
	if err := s.SaveScan(ctx, first, "owner"); err != nil {
		t.Fatalf("первый скан: %v", err)
	}
	second := ScanResult{
		Started:  now.Add(-time.Minute),
		Finished: now.Add(time.Minute),
		Subnets:  []string{"10.0.0.0/24"},
		Hosts:    []model.Host{hostFix(t, "10.0.0.9", "ghost", now.Add(time.Minute))},
		Topology: model.NewTopology(),
	}
	if err := s.SaveScan(ctx, second, "owner"); err != nil {
		t.Fatalf("второй скан: %v", err)
	}
	if got := ipHostCount(t, s, "10.0.0.9"); got != 0 {
		t.Fatalf("ip-дубль создан: строк %d", got)
	}
}

// Ручная классификация ip-хоста не затирается повторным сканом.
func TestSaveScanIPHostClassKept(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	now := time.Now()

	first := ScanResult{
		Started:  now.Add(-time.Minute),
		Finished: now,
		Subnets:  []string{"10.0.0.0/24"},
		Hosts:    []model.Host{hostFix(t, "10.0.0.9", "", now)},
		Topology: model.NewTopology(),
	}
	if err := s.SaveScan(ctx, first, "owner"); err != nil {
		t.Fatalf("первый скан: %v", err)
	}
	guest := model.ClassGuest
	if err := s.UpdateDevice(ctx, "ip:10.0.0.9", Update{Class: &guest}, "owner"); err != nil {
		t.Fatalf("смена класса: %v", err)
	}
	again := ScanResult{
		Started:  now.Add(-time.Minute),
		Finished: now.Add(time.Hour),
		Subnets:  []string{"10.0.0.0/24"},
		Hosts:    []model.Host{hostFix(t, "10.0.0.9", "", now.Add(time.Hour))},
		Topology: model.NewTopology(),
	}
	if err := s.SaveScan(ctx, again, "owner"); err != nil {
		t.Fatalf("второй скан: %v", err)
	}
	var class string
	if err := s.DB().QueryRow(
		`SELECT class FROM devices WHERE id = 'ip:10.0.0.9'`,
	).Scan(&class); err != nil {
		t.Fatalf("чтение класса: %v", err)
	}
	if class != string(model.ClassGuest) {
		t.Fatalf("класс %q, хочу guest", class)
	}
}

// ListDevices отдаёт пустые срезы, а не null: интерфейс вызывает
// .join по ним (хвост волны 1, поймано смоком NR-023).
func TestListDevicesSlicesNotNull(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	now := time.Now()
	scan := ScanResult{
		Started:  now.Add(-time.Minute),
		Finished: now,
		Subnets:  []string{"10.0.0.0/24"},
		Devices:  []model.Device{testDevice(t, "02:00:00:00:00:42", "10.0.0.42", "box", now)},
		Topology: model.NewTopology(),
	}
	if err := s.SaveScan(ctx, scan, "owner"); err != nil {
		t.Fatalf("SaveScan: %v", err)
	}
	devs, err := s.ListDevices(ctx)
	if err != nil {
		t.Fatalf("ListDevices: %v", err)
	}
	if len(devs) != 1 {
		t.Fatalf("устройств %d, хочу 1", len(devs))
	}
	d := devs[0]
	if d.IPs == nil || d.Names == nil || d.Observations == nil {
		t.Fatalf("срезы nil: ips=%v names=%v obs=%v", d.IPs == nil, d.Names == nil, d.Observations == nil)
	}
}
