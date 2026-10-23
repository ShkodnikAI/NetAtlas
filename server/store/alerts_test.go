package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/ShkodnikAI/NetAtlas/internal/model"
)

// Открытое оповещение создаётся один раз и закрывается сменой класса.
func TestAlertsSingleAndClose(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	const mac = "00:00:00:00:00:0b"
	now := time.Now()

	if err := s.SaveScan(ctx, scanFix(t, now, mac, "10.0.0.11", "new"), "owner"); err != nil {
		t.Fatalf("первый скан: %v", err)
	}
	alerts, err := s.ListAlerts(ctx)
	if err != nil || len(alerts) != 1 {
		t.Fatalf("оповещений = %d (err %v), хочу 1", len(alerts), err)
	}
	if alerts[0].DeviceID != mac || !alerts[0].Open {
		t.Fatalf("оповещение = %+v", alerts[0])
	}

	// Повторное сканирование до классификации: второго нет.
	if err := s.SaveScan(ctx, scanFix(t, now.Add(time.Hour), mac, "10.0.0.11", "new"), "owner"); err != nil {
		t.Fatalf("второй скан: %v", err)
	}
	if alerts, err = s.ListAlerts(ctx); err != nil || len(alerts) != 1 {
		t.Fatalf("после повтора оповещений = %d (err %v), хочу 1", len(alerts), err)
	}

	// Разбор владельцем закрывает.
	alertID := alerts[0].ID
	if err := s.AckAlert(ctx, alertID, "owner"); err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if alerts, err = s.ListAlerts(ctx); err != nil || len(alerts) != 0 {
		t.Fatalf("после разбора оповещений = %d (err %v), хочу 0", len(alerts), err)
	}
	if err := s.AckAlert(ctx, alertID, "owner"); !errors.Is(err, ErrNotManual) {
		t.Fatalf("повторный разбор: %v, хочу ErrNotManual (уже закрыто)", err)
	}
}

// Новое устройство, уже классифицированное владельцем до скана, не
// оповещает повторно; смена класса закрывает оповещение.
func TestAlertsCloseOnClassChange(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	const mac = "00:00:00:00:00:0c"
	now := time.Now()

	if err := s.SaveScan(ctx, scanFix(t, now, mac, "10.0.0.12", "two"), "owner"); err != nil {
		t.Fatalf("скан: %v", err)
	}
	alerts, err := s.ListAlerts(ctx)
	if err != nil || len(alerts) != 1 {
		t.Fatalf("оповещений = %d (err %v), хочу 1", len(alerts), err)
	}
	guest := model.ClassGuest
	if err := s.UpdateDevice(ctx, mac, Update{Class: &guest}, "owner"); err != nil {
		t.Fatalf("смена класса: %v", err)
	}
	if alerts, err = s.ListAlerts(ctx); err != nil || len(alerts) != 0 {
		t.Fatalf("после смены класса оповещений = %d (err %v), хочу 0", len(alerts), err)
	}

	// Классифицированное устройство при повторном скане не
	// оповещает снова и не теряет класс.
	if err := s.SaveScan(ctx, scanFix(t, now.Add(2*time.Hour), mac, "10.0.0.12", "two"), "owner"); err != nil {
		t.Fatalf("повторный скан: %v", err)
	}
	if alerts, err = s.ListAlerts(ctx); err != nil || len(alerts) != 0 {
		t.Fatalf("оповещений после скана гостя = %d (err %v), хочу 0", len(alerts), err)
	}
	info, err := s.Device(ctx, mac)
	if err != nil {
		t.Fatalf("карточка: %v", err)
	}
	if info.Class != model.ClassGuest {
		t.Fatalf("класс затёрт сканом: %+v", info)
	}
}

// Разбор несуществующего и уже закрытого оповещения — ошибки.
func TestAckAlertValidation(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	if err := s.AckAlert(ctx, 99, "owner"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("чужой id: %v, хочу ErrNotFound", err)
	}
}

// Миграция 5 на заполненной базе: существующие данные целы.
func TestMigrationsV5OnFilled(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "netatlas.db")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("первое открытие: %v", err)
	}
	ctx := context.Background()
	const mac = "00:00:00:00:00:0b"
	if err := s.SaveScan(ctx, scanFix(t, time.Now(), mac, "10.0.0.11", "keeper"), "owner"); err != nil {
		t.Fatalf("скан: %v", err)
	}
	s.Close()

	s2, err := Open(path)
	if err != nil {
		t.Fatalf("повторное открытие: %v", err)
	}
	defer s2.Close()
	if _, err := s2.Device(ctx, mac); err != nil {
		t.Fatalf("устройство потеряно миграцией: %v", err)
	}
}
