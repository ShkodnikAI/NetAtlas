package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/ShkodnikAI/NetAtlas/internal/model"
	"github.com/ShkodnikAI/NetAtlas/server/audit"
)

// ScanResult — итог одного сканирования для сохранения: устройства и
// топология из scanner.Result, границы скана и время.
type ScanResult struct {
	Started  time.Time      `json:"started"`
	Finished time.Time      `json:"finished"`
	Subnets  []string       `json:"subnets"`
	Devices  []model.Device `json:"devices"`
	Topology model.Topology `json:"topology"`
}

// SaveScan сохраняет результат сканирования одной транзакцией:
// строку в scans, устройства (добавление и обновление по ID), их IP,
// имена и наблюдения, связи из топологии. Ручные поля (class, label,
// verified, manual-элементы и связи) не затираются. Запись пишется в
// аудит в той же транзакции: ошибка в середине откатывает всё,
// включая строку аудита.
func (s *Store) SaveScan(ctx context.Context, scan ScanResult, actor string) error {
	now := scan.Finished
	if now.IsZero() {
		now = time.Now()
	}
	if scan.Started.IsZero() {
		scan.Started = now
	}
	subnets := scan.Subnets
	if subnets == nil {
		subnets = []string{}
	}
	subnetsJSON, err := json.Marshal(subnets)
	if err != nil {
		return fmt.Errorf("store: подсети скана: %w", err)
	}
	// kind узлов топологии: устройство, ставшее узлом switch, — коммутатор.
	switchIDs := map[string]bool{}
	for _, n := range scan.Topology.Nodes {
		if n.Kind == model.NodeKindSwitch {
			switchIDs[n.ID] = true
		}
	}
	detail, err := json.Marshal(struct {
		Devices  int      `json:"devices"`
		Links    int      `json:"links"`
		Subnets  []string `json:"subnets"`
		Finished string   `json:"finished"`
	}{
		Devices:  len(scan.Devices),
		Links:    len(scan.Topology.Links),
		Subnets:  subnets,
		Finished: now.UTC().Format(time.RFC3339Nano),
	})
	if err != nil {
		return fmt.Errorf("store: сводка скана: %w", err)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: транзакция скана: %w", err)
	}
	defer tx.Rollback()

	// Аудит первым: транзакция обязана откатить и его при ошибке.
	if _, err := audit.Append(ctx, tx, audit.Entry{
		Actor:  actor,
		Action: "save_scan",
		Target: "scan",
		Result: "ok",
		Detail: string(detail),
	}); err != nil {
		return err
	}
	started := scan.Started.UTC().Format(time.RFC3339Nano)
	finished := now.UTC().Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO scans (started, finished, subnets) VALUES (?, ?, ?)`,
		started, finished, string(subnetsJSON)); err != nil {
		return fmt.Errorf("store: строка скана: %w", err)
	}
	for _, d := range scan.Devices {
		if err := upsertDevice(ctx, tx, d, switchIDs[d.ID], now); err != nil {
			return err
		}
	}
	for _, l := range scan.Topology.Links {
		if err := upsertLink(ctx, tx, l); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// upsertDevice добавляет или обновляет устройство и его данные.
// Обновляются только данные сканера: hostname, vendor, ssid, IP,
// имена, наблюдения, last_seen, kind. class, label, verified и manual
// устройства не трогаются.
func upsertDevice(ctx context.Context, tx *sql.Tx, d model.Device, isSwitch bool, now time.Time) error {
	if d.ID == "" || strings.HasPrefix(d.ID, "manual:") {
		return fmt.Errorf("store: устройство без MAC-идентификатора %q", d.ID)
	}
	if _, err := model.NormalizeMAC(d.ID); err != nil {
		return fmt.Errorf("store: устройство %q: %w", d.ID, err)
	}
	for _, ip := range d.IPs {
		if !ip.IsValid() {
			return fmt.Errorf("store: устройство %s: недопустимый адрес", d.ID)
		}
	}
	names := make([]model.Name, 0, len(d.Names))
	for _, n := range d.Names {
		fixed, err := model.NewName(n.Source, n.Name, n.Seen)
		if err != nil {
			return fmt.Errorf("store: устройство %s: имя: %w", d.ID, err)
		}
		names = append(names, fixed)
	}
	kind := model.NodeKindDevice
	if isSwitch {
		kind = model.NodeKindSwitch
	}
	ts := now.UTC().Format(time.RFC3339Nano)
	hostname := strings.TrimSpace(d.Hostname)
	vendor := strings.TrimSpace(d.Vendor)
	ssid := strings.TrimSpace(d.SSID)

	if _, err := tx.ExecContext(ctx, `INSERT INTO devices
		(id, kind, class, label, hostname, vendor, ssid, manual, verified, first_seen, last_seen)
		VALUES (?, ?, 'unknown', '', ?, ?, ?, 0, 0, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			kind = excluded.kind,
			hostname = CASE WHEN excluded.hostname != '' THEN excluded.hostname ELSE devices.hostname END,
			vendor   = CASE WHEN excluded.vendor   != '' THEN excluded.vendor   ELSE devices.vendor   END,
			ssid     = CASE WHEN excluded.ssid     != '' THEN excluded.ssid     ELSE devices.ssid     END,
			last_seen = excluded.last_seen`,
		d.ID, kind, hostname, vendor, ssid, ts, ts); err != nil {
		return fmt.Errorf("store: устройство %s: %w", d.ID, err)
	}
	for _, ip := range d.IPs {
		if _, err := tx.ExecContext(ctx,
			`INSERT OR IGNORE INTO device_ips (device_id, ip) VALUES (?, ?)`,
			d.ID, ip.String()); err != nil {
			return fmt.Errorf("store: адрес устройства %s: %w", d.ID, err)
		}
	}
	for _, n := range names {
		if _, err := tx.ExecContext(ctx, `INSERT INTO device_names (device_id, source, name, seen)
			VALUES (?, ?, ?, ?)
			ON CONFLICT(device_id, source, name) DO UPDATE SET seen = excluded.seen`,
			d.ID, n.Source, n.Name, n.Seen.UTC().Format(time.RFC3339Nano)); err != nil {
			return fmt.Errorf("store: имя устройства %s: %w", d.ID, err)
		}
	}
	for _, o := range d.Observations {
		seen := o.Seen
		if seen.IsZero() {
			seen = now
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO observations (device_id, source, seen)
			VALUES (?, ?, ?)
			ON CONFLICT(device_id, source) DO UPDATE SET seen = excluded.seen`,
			d.ID, o.Source, seen.UTC().Format(time.RFC3339Nano)); err != nil {
			return fmt.Errorf("store: наблюдение устройства %s: %w", d.ID, err)
		}
	}
	return nil
}

// linkSources — источники связей, допустимые из сканера.
var linkSources = map[string]bool{
	model.LinkSourceLLDP:     true,
	model.LinkSourceFDB:      true,
	model.LinkSourceInferred: true,
}

// upsertLink добавляет или обновляет связь по концам: id связи —
// SHA-256 канонических концов, поэтому повторное сканирование
// обновляет существующую строку. Ручные связи не изменяются.
func upsertLink(ctx context.Context, tx *sql.Tx, l model.Link) error {
	a, aPort, b, bPort := l.A, l.APort, l.B, l.BPort
	if a == "" || b == "" || a == b {
		return fmt.Errorf("store: связь с пустыми или совпадающими концами %q–%q", a, b)
	}
	if b < a {
		a, aPort, b, bPort = b, bPort, a, aPort
	}
	if !linkSources[l.Source] {
		return fmt.Errorf("store: связь %s–%s: источник %q", a, b, l.Source)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO links
		(id, a, a_port, b, b_port, source, manual, verified)
		VALUES (?, ?, ?, ?, ?, ?, 0, 0)
		ON CONFLICT(a, a_port, b, b_port) DO UPDATE SET
			source   = CASE WHEN links.manual = 1 THEN links.source ELSE excluded.source END,
			manual   = links.manual,
			verified = links.verified`,
		linkID(a, aPort, b, bPort), a, aPort, b, bPort, l.Source); err != nil {
		return fmt.Errorf("store: связь %s–%s: %w", a, b, err)
	}
	return nil
}

// linkID — идентификатор связи по концам: SHA-256 канонической строки.
func linkID(a, aPort, b, bPort string) string {
	h := sha256.New()
	for _, part := range []string{a, aPort, b, bPort} {
		h.Write([]byte(part))
		h.Write([]byte{0x1f})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// ipFromAddr — строка адреса; паники исключены проверкой валидности.
func ipFromAddr(a netip.Addr) string {
	if !a.IsValid() {
		return ""
	}
	return a.String()
}

// errNotFoundIf — короткая замена сравнения sql.ErrNoRows.
func errNotFoundIf(err error, what string) error {
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("%s: %w", what, ErrNotFound)
	}
	return err
}
