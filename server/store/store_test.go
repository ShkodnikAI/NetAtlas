package store

import (
	"context"
	"database/sql"
	"errors"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/ShkodnikAI/NetAtlas/internal/model"
	"github.com/ShkodnikAI/NetAtlas/server/audit"
)

// openTest — хранилище на временной базе.
func openTest(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "netatlas.db"))
	if err != nil {
		t.Fatalf("открытие: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// testDevice — устройство с IP, именем и наблюдением для фикстур.
func testDevice(t *testing.T, mac, ip, name string, seen time.Time) model.Device {
	t.Helper()
	d, err := model.NewDevice(mac)
	if err != nil {
		t.Fatalf("устройство %s: %v", mac, err)
	}
	if ip != "" {
		a, err := netip.ParseAddr(ip)
		if err != nil {
			t.Fatalf("IP %s: %v", ip, err)
		}
		d.IPs = append(d.IPs, a)
	}
	if name != "" {
		n, err := model.NewName(model.NameSourceNetBIOS, name, seen)
		if err != nil {
			t.Fatalf("имя %s: %v", name, err)
		}
		d.Names = append(d.Names, n)
	}
	d.Observations = append(d.Observations, model.Observation{Source: "arp", Seen: seen})
	return d
}

// scanFix — результат сканера с одним устройством и связью.
func scanFix(t *testing.T, now time.Time, mac, ip, name string) ScanResult {
	t.Helper()
	d := testDevice(t, mac, ip, name, now)
	topo := model.NewTopology()
	topo.Nodes = append(topo.Nodes, model.Node{ID: mac, Kind: model.NodeKindDevice, Label: name})
	topo.Links = append(topo.Links, model.Link{
		A: mac, APort: "Gi0/1", B: "00:00:00:00:00:01", BPort: "Gi0/24", Source: model.LinkSourceLLDP,
	})
	return ScanResult{
		Started:  now.Add(-time.Minute),
		Finished: now,
		Subnets:  []string{"10.0.0.0/24"},
		Devices:  []model.Device{d},
		Topology: topo,
	}
}

// Миграции на пустой базе: версия 3, повторный запуск ничего не меняет.
func TestMigrationsEmptyAndRepeat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "netatlas.db")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("открытие: %v", err)
	}
	ctx := context.Background()
	v, err := s.SchemaVersion(ctx)
	if err != nil || v != 3 {
		t.Fatalf("версия = %d (err %v), хочу 3", v, err)
	}
	if _, err := s.AddManualDevice(ctx, model.NodeKindDevice, "ручной", "owner"); err != nil {
		t.Fatalf("ручной элемент: %v", err)
	}
	s.Close()

	// Повторное открытие заполненной базы: версия та же, данные те же.
	s2, err := Open(path)
	if err != nil {
		t.Fatalf("повторное открытие: %v", err)
	}
	defer s2.Close()
	if v, err := s2.SchemaVersion(ctx); err != nil || v != 3 {
		t.Fatalf("версия после повтора = %d (err %v), хочу 3", v, err)
	}
	devs, err := s2.ListDevices(ctx)
	if err != nil || len(devs) != 1 {
		t.Fatalf("устройств = %d (err %v), хочу 1 (миграция не пересоздала таблицы)", len(devs), err)
	}
}

// SaveScan дважды: нет дублей, ручные поля не затираются, last_seen
// обновляется.
func TestSaveScanTwicePreservesManualFields(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	const mac = "00:00:00:00:00:0b"

	if err := s.SaveScan(ctx, scanFix(t, now, mac, "10.0.0.11", "printer"), "owner"); err != nil {
		t.Fatalf("первый скан: %v", err)
	}
	guest := model.ClassGuest
	label := "лаборатория"
	verified := true
	if err := s.UpdateDevice(ctx, mac, Update{Class: &guest, Name: &label, Verified: &verified}, "owner"); err != nil {
		t.Fatalf("ручная правка: %v", err)
	}
	if err := s.SaveScan(ctx, scanFix(t, now.Add(time.Hour), mac, "10.0.0.11", "printer"), "owner"); err != nil {
		t.Fatalf("второй скан: %v", err)
	}

	info, err := s.Device(ctx, mac)
	if err != nil {
		t.Fatalf("карточка: %v", err)
	}
	if info.Class != model.ClassGuest {
		t.Errorf("класс = %s, хочу guest (скан не затирает класс)", info.Class)
	}
	if !info.Verified {
		t.Errorf("verified сброшен сканом, хочу true")
	}
	if got := info.Names; len(got) != 1 || got[0].Name != "printer" {
		t.Errorf("имён = %+v, хочу одно printer (без дублей)", got)
	}
	if got := info.Observations; len(got) != 1 {
		t.Errorf("наблюдений = %+v, хочу одно (без дублей)", got)
	}
	if got := info.IPs; len(got) != 1 {
		t.Errorf("адресов = %+v, хочу один (без дублей)", got)
	}
	if !info.LastSeenIsFresh(t, now.Add(time.Hour)) {
		t.Errorf("last_seen не обновился вторым сканом")
	}

	// Связь из скана: одна, дубликат при повторном скане не создаётся.
	g, err := s.Topology(ctx)
	if err != nil {
		t.Fatalf("топология: %v", err)
	}
	if len(g.Links) != 1 {
		t.Errorf("связей = %d, хочу 1 (повтор не дублирует): %+v", len(g.Links), g.Links)
	}
	if g.Links[0].Manual {
		t.Errorf("скан-связь помечена ручной: %+v", g.Links[0])
	}
}

// LastSeenIsFresh проверяет, что last_seen устройства в карточке не
// раньше указанного момента (вспомогательный метод теста).
func (d DeviceInfo) LastSeenIsFresh(t *testing.T, notBefore time.Time) bool {
	t.Helper()
	return !d.LastSeenAt(t).Before(notBefore)
}

// LastSeenAt возвращает время last_seen из наблюдений (для теста).
func (d DeviceInfo) LastSeenAt(t *testing.T) time.Time {
	t.Helper()
	// last_seen хранится в хранилище; в карточке он виден через
	// наблюдение «arp» (обновляется при каждом скане).
	for _, o := range d.Observations {
		if o.Source == "arp" {
			return o.Seen
		}
	}
	return time.Time{}
}

// Удаляется только ручное устройство; найденное — отказ.
func TestDeleteManualOnly(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	now := time.Now()

	id, err := s.AddManualDevice(ctx, model.NodeKindDevice, "ручной", "owner")
	if err != nil {
		t.Fatalf("ручной элемент: %v", err)
	}
	if err := s.DeleteManualDevice(ctx, id, "owner"); err != nil {
		t.Fatalf("удаление ручного: %v", err)
	}
	if _, err := s.Device(ctx, id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("после удаления: %v, хочу ErrNotFound", err)
	}

	const mac = "00:00:00:00:00:0c"
	if err := s.SaveScan(ctx, scanFix(t, now, mac, "10.0.0.12", "found"), "owner"); err != nil {
		t.Fatalf("скан: %v", err)
	}
	if err := s.DeleteManualDevice(ctx, mac, "owner"); !errors.Is(err, ErrNotManual) {
		t.Fatalf("удаление найденного: %v, хочу ErrNotManual", err)
	}
}

// Прямые UPDATE и DELETE по audit_log обязаны падать (триггеры).
func TestAuditAppendOnly(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	id, err := s.AddManualDevice(ctx, model.NodeKindSwitch, "коммутатор", "owner")
	if err != nil {
		t.Fatalf("ручной элемент: %v", err)
	}
	_ = id

	if _, err := s.DB().ExecContext(ctx, `UPDATE audit_log SET actor = 'злоумышленник'`); err == nil {
		t.Fatalf("UPDATE audit_log прошёл, хочу ошибку триггера")
	}
	if _, err := s.DB().ExecContext(ctx, `DELETE FROM audit_log`); err == nil {
		t.Fatalf("DELETE FROM audit_log прошёл, хочу ошибку триггера")
	}
	entries, err := audit.List(ctx, s.DB(), 100, 0)
	if err != nil || len(entries) != 1 {
		t.Fatalf("записей в журнале = %d (err %v), хочу 1", len(entries), err)
	}
	if err := audit.Verify(ctx, s.DB()); err != nil {
		t.Fatalf("цепочка сломана без вмешательства: %v", err)
	}
}

// Verify находит подмену поля и разрыв цепочки.
func TestAuditVerifyCatchesTamper(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if _, err := s.AddManualDevice(ctx, model.NodeKindDevice, "элемент", "owner"); err != nil {
			t.Fatalf("ручной элемент %d: %v", i, err)
		}
	}
	// Тестовый доступ к базе: триггеры снимаются явно, чтобы
	// симулировать атаку поверх копии схемы.
	for _, trig := range []string{"audit_log_no_update", "audit_log_no_delete"} {
		if _, err := s.DB().ExecContext(ctx, `DROP TRIGGER `+trig); err != nil {
			t.Fatalf("снятие %s: %v", trig, err)
		}
	}
	if _, err := s.DB().ExecContext(ctx,
		`UPDATE audit_log SET actor = 'злоумышленник' WHERE id = 2`); err != nil {
		t.Fatalf("подмена: %v", err)
	}
	if err := audit.Verify(ctx, s.DB()); err == nil {
		t.Fatalf("Verify не нашёл подмену поля")
	}
	// Разрыв: удаление средней записи.
	if _, err := s.DB().ExecContext(ctx, `DELETE FROM audit_log WHERE id = 2`); err != nil {
		t.Fatalf("удаление записи: %v", err)
	}
	if err := audit.Verify(ctx, s.DB()); err == nil {
		t.Fatalf("Verify не нашёл разрыв цепочки")
	}
}

// Ошибка в середине SaveScan не оставляет ни данных, ни аудита.
func TestSaveScanAtomic(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	now := time.Now()
	scan := scanFix(t, now, "00:00:00:00:00:0d", "10.0.0.13", "ok")
	bad := testDevice(t, "00:00:00:00:00:0e", "10.0.0.14", "evil", now)
	bad.Names = append(bad.Names, model.Name{Source: "злой-источник", Name: "x", Seen: now})
	scan.Devices = append(scan.Devices, bad)

	if err := s.SaveScan(ctx, scan, "owner"); err == nil {
		t.Fatalf("скан с невалидным именем прошёл, хочу ошибку в середине транзакции")
	}
	var devices, audits int
	if err := s.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM devices`).Scan(&devices); err != nil {
		t.Fatalf("устройства: %v", err)
	}
	if err := s.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_log`).Scan(&audits); err != nil {
		t.Fatalf("журнал: %v", err)
	}
	if devices != 0 || audits != 0 {
		t.Fatalf("после ошибки: устройств %d, записей аудита %d; хочу 0 и 0 (атомарность)", devices, audits)
	}
}

// Backup: копия создаётся, не перезаписывается, читается.
func TestBackupCreatesAndRefusesOverwrite(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	const mac = "00:00:00:00:00:0f"
	if err := s.SaveScan(ctx, scanFix(t, time.Now(), mac, "10.0.0.15", "keeper"), "owner"); err != nil {
		t.Fatalf("скан: %v", err)
	}
	path := filepath.Join(t.TempDir(), "backup.db")
	if err := s.Backup(ctx, path); err != nil {
		t.Fatalf("копия: %v", err)
	}
	if err := s.Backup(ctx, path); !errors.Is(err, ErrBackupExists) {
		t.Fatalf("повторная копия: %v, хочу ErrBackupExists", err)
	}
	bk, err := Open(path)
	if err != nil {
		t.Fatalf("открытие копии: %v", err)
	}
	defer bk.Close()
	if _, err := bk.Device(ctx, mac); err != nil {
		t.Fatalf("устройство в копии: %v", err)
	}
	if err := audit.Verify(ctx, bk.DB()); err != nil {
		t.Fatalf("цепочка в копии: %v", err)
	}
}

// Топология: ручные элементы и связи помечены, найденные — нет.
func TestTopologyFlagsAndManual(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	now := time.Now()
	const swMac = "00:00:00:00:00:0b"
	if err := s.SaveScan(ctx, scanFix(t, now, swMac, "10.0.0.11", "pc"), "owner"); err != nil {
		t.Fatalf("скан: %v", err)
	}
	g, err := s.Topology(ctx)
	if err != nil {
		t.Fatalf("топология: %v", err)
	}
	if len(g.Nodes) != 2 || len(g.Links) != 1 {
		t.Fatalf("граф: %d узлов, %d связей; хочу 2 и 1", len(g.Nodes), len(g.Links))
	}
	for _, l := range g.Links {
		if l.Manual || l.Verified {
			t.Errorf("скан-связь помечена ручной/проверенной: %+v", l)
		}
	}

	id, err := s.AddManualDevice(ctx, model.NodeKindDevice, "новый", "owner")
	if err != nil {
		t.Fatalf("ручной элемент: %v", err)
	}
	linkID, err := s.AddManualLink(ctx, id, "", swMac, "Gi0/24", "owner")
	if err != nil {
		t.Fatalf("ручная связь: %v", err)
	}
	g, err = s.Topology(ctx)
	if err != nil {
		t.Fatalf("топология: %v", err)
	}
	if len(g.Links) != 2 {
		t.Fatalf("связей = %d, хочу 2", len(g.Links))
	}
	found := false
	for _, n := range g.Nodes {
		if n.ID == id {
			found = true
			if !n.Manual || n.Verified {
				t.Errorf("ручной узел: manual=%v verified=%v, хочу true/false", n.Manual, n.Verified)
			}
			if n.Label != "новый" {
				t.Errorf("подпись ручного узла = %q, хочу \"новый\"", n.Label)
			}
		}
	}
	if !found {
		t.Fatalf("ручной узел не в графе")
	}
	manual := 0
	for _, l := range g.Links {
		if l.Manual {
			manual++
		}
	}
	if manual != 1 {
		t.Fatalf("ручных связей = %d, хочу 1", manual)
	}
	if err := s.DeleteManualLink(ctx, linkID, "owner"); err != nil {
		t.Fatalf("удаление ручной связи: %v", err)
	}
	if err := s.DeleteManualLink(ctx, linkID, "owner"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("повторное удаление: %v, хочу ErrNotFound", err)
	}
}

// Класс проверяется: недопустимый класс не записывается.
func TestUpdateDeviceRejectsBadClass(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	const mac = "00:00:00:00:00:0b"
	if err := s.SaveScan(ctx, scanFix(t, time.Now(), mac, "10.0.0.11", "pc"), "owner"); err != nil {
		t.Fatalf("скан: %v", err)
	}
	bad := model.Class("самозванец")
	if err := s.UpdateDevice(ctx, mac, Update{Class: &bad}, "owner"); err == nil {
		t.Fatalf("недопустимый класс прошёл")
	}
	if _, err := s.Device(ctx, "00:00:00:00:00:99"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("чужое устройство: %v, хочу ErrNotFound", err)
	}
}

// Скриптовая проверка отсутствия sql.ErrNoRows в ListDevices на пустой базе.
func TestListDevicesEmpty(t *testing.T) {
	s := openTest(t)
	devs, err := s.ListDevices(context.Background())
	if err != nil {
		t.Fatalf("список: %v", err)
	}
	if devs == nil || len(devs) != 0 {
		t.Fatalf("список = %v, хочу пустой непустой-nil срез", devs)
	}
}

// Гарантия: строки запросов со склейкой данных запрещены — проверяем,
// что база переживает данные с кавычками (параметры, не конкатенация).
func TestQuotesSafe(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	id, err := s.AddManualDevice(ctx, model.NodeKindDevice, "'); DROP TABLE devices;--", "owner")
	if err != nil {
		t.Fatalf("вредоносное имя: %v", err)
	}
	if _, err := s.Device(ctx, id); err != nil {
		t.Fatalf("чтение после вредоносного имени: %v", err)
	}
	var n int
	if err := s.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM devices`).Scan(&n); err != nil {
		t.Fatalf("таблица устройств повреждена: %v", err)
	}
	if n != 1 {
		t.Fatalf("устройств = %d, хочу 1", n)
	}
}

// audit_tx — заглушка для статической проверки интерфейса: *sql.Tx и
// *sql.DB подходят под audit.DBTX.
var (
	_ audit.DBTX = (*sql.Tx)(nil)
	_ audit.DBTX = (*sql.DB)(nil)
)
