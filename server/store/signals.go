// Сигналы внимания на карте (NR-033 п.4): данные для вычисления
// сигналов — из уже собранных данных (сканы, оповещения, агенты,
// аудит). Сеть пакет не читает и не пишет. Отложенные («Игнорировать
// на N дней») сигналы хранятся в signal_snoozes (миграция 17).

package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/ShkodnikAI/NetAtlas/server/audit"
)

// SignalDeviceRow — минимальные сведения устройства для вычисления
// сигналов: класс, ручной элемент, проверенность, последнее
// обнаружение.
type SignalDeviceRow struct {
	ID       string
	Class    string
	Manual   bool
	Verified bool
	LastSeen time.Time
	IPs      []string
}

// SignalDevices — все устройства с адресами (без имён и наблюдений:
// для сигналов достаточно адресов и времени последнего обнаружения).
func (s *Store) SignalDevices(ctx context.Context) ([]SignalDeviceRow, error) {
	devs, err := s.db.QueryContext(ctx,
		`SELECT id, class, manual, verified, last_seen FROM devices ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("store: устройства для сигналов: %w", err)
	}
	defer devs.Close()
	out := []SignalDeviceRow{}
	byID := map[string]*SignalDeviceRow{}
	for devs.Next() {
		var r SignalDeviceRow
		var lastSeen string
		if err := devs.Scan(&r.ID, &r.Class, &r.Manual, &r.Verified, &lastSeen); err != nil {
			return nil, fmt.Errorf("store: устройство для сигналов: %w", err)
		}
		if lastSeen != "" {
			t, err := time.Parse(time.RFC3339Nano, lastSeen)
			if err == nil {
				r.LastSeen = t
			}
		}
		r.IPs = []string{}
		out = append(out, r)
		byID[r.ID] = &out[len(out)-1]
	}
	if err := devs.Err(); err != nil {
		return nil, fmt.Errorf("store: устройства для сигналов: %w", err)
	}
	ips, err := s.db.QueryContext(ctx, `SELECT device_id, ip FROM device_ips ORDER BY device_id, ip`)
	if err != nil {
		return nil, fmt.Errorf("store: адреса для сигналов: %w", err)
	}
	defer ips.Close()
	for ips.Next() {
		var dev, ip string
		if err := ips.Scan(&dev, &ip); err != nil {
			return nil, fmt.Errorf("store: адрес для сигналов: %w", err)
		}
		if r := byID[dev]; r != nil {
			r.IPs = append(r.IPs, ip)
		}
	}
	if err := ips.Err(); err != nil {
		return nil, fmt.Errorf("store: адреса для сигналов: %w", err)
	}
	return out, nil
}

// OpenAlert — открытое оповещение о новом неизвестном устройстве.
type OpenAlert struct {
	ID       int64     `json:"id"`
	DeviceID string    `json:"device_id"`
	Created  time.Time `json:"created"`
}

// OpenAlerts — все открытые оповещения (новые сверху).
func (s *Store) OpenAlerts(ctx context.Context) ([]OpenAlert, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, device_id, created FROM alerts WHERE closed = '' ORDER BY id DESC`)
	if err != nil {
		return nil, fmt.Errorf("store: открытые оповещения: %w", err)
	}
	defer rows.Close()
	out := []OpenAlert{}
	for rows.Next() {
		var a OpenAlert
		var created string
		if err := rows.Scan(&a.ID, &a.DeviceID, &created); err != nil {
			return nil, fmt.Errorf("store: оповещение: %w", err)
		}
		if created != "" {
			if t, err := time.Parse(time.RFC3339Nano, created); err == nil {
				a.Created = t
			}
		}
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: открытые оповещения: %w", err)
	}
	return out, nil
}

// OpenAlertsByDevice — открытые оповещения одного устройства.
func (s *Store) OpenAlertsByDevice(ctx context.Context, deviceID string) ([]OpenAlert, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, device_id, created FROM alerts WHERE closed = '' AND device_id = ? ORDER BY id DESC`, deviceID)
	if err != nil {
		return nil, fmt.Errorf("store: оповещения устройства: %w", err)
	}
	defer rows.Close()
	out := []OpenAlert{}
	for rows.Next() {
		var a OpenAlert
		var created string
		if err := rows.Scan(&a.ID, &a.DeviceID, &created); err != nil {
			return nil, fmt.Errorf("store: оповещение устройства: %w", err)
		}
		if created != "" {
			if t, err := time.Parse(time.RFC3339Nano, created); err == nil {
				a.Created = t
			}
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// AgentRef — агент, связанный с устройством по MAC.
type AgentRef struct {
	ID       string `json:"id"`
	Hostname string `json:"hostname,omitempty"`
}

// agentMACEntry — строка разбора mac_list агента.
type agentMACEntry struct {
	Agent    AgentRef
	MACs     []string
	LastSeen time.Time
}

// AgentsByMAC — карта «MAC устройства → агент»: агенты пишут список
// MAC своих адаптеров при регистрации (agents.mac_list, JSON).
func (s *Store) AgentsByMAC(ctx context.Context) (map[string]AgentRef, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, hostname, mac_list FROM agents WHERE status = 'active' ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("store: агенты: %w", err)
	}
	defer rows.Close()
	out := map[string]AgentRef{}
	for rows.Next() {
		var id, hostname, macsJSON string
		if err := rows.Scan(&id, &hostname, &macsJSON); err != nil {
			return nil, fmt.Errorf("store: агент: %w", err)
		}
		var macs []string
		if macsJSON != "" {
			if err := json.Unmarshal([]byte(macsJSON), &macs); err != nil {
				// mac_list повреждён — агент без привязки MAC, не ошибка всего запроса
				macs = nil
			}
		}
		for _, mac := range macs {
			if mac == "" {
				continue
			}
			if _, taken := out[mac]; !taken {
				out[mac] = AgentRef{ID: id, Hostname: hostname}
			}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: агенты: %w", err)
	}
	return out, nil
}

// SnoozeSignal прячет сигнал вида kind у устройства до времени until.
// Повторный вызов перезаписывает срок (одно решение на пару
// устройство+вид).
func (s *Store) SnoozeSignal(ctx context.Context, deviceID, kind string, until time.Time, actor string, now time.Time) error {
	if deviceID == "" || kind == "" {
		return fmt.Errorf("store: отложенный сигнал: пустое устройство или вид")
	}
	if !until.After(now) {
		return fmt.Errorf("store: отложенный сигнал: срок в прошлом")
	}
	if _, err := audit.Append(ctx, s.db, audit.Entry{
		Actor: actor, Action: "signal_snooze", Target: deviceID, Result: "ok",
		Detail: fmt.Sprintf("kind=%s until=%s", kind, until.UTC().Format(time.RFC3339)),
	}); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO signal_snoozes (device_id, kind, until, created_at, actor)
                 VALUES (?, ?, ?, ?, ?)
                 ON CONFLICT(device_id, kind) DO UPDATE SET until = excluded.until,
                   created_at = excluded.created_at, actor = excluded.actor`,
		deviceID, kind, until.UTC().Format(time.RFC3339Nano), now.UTC().Format(time.RFC3339Nano), actor)
	if err != nil {
		return fmt.Errorf("store: отложенный сигнал: %w", err)
	}
	return nil
}

// ActiveSnoozes — карта «device_id\x00kind» → true: сигнал скрыт до
// срока (решения «Игнорировать на N дней», ещё не истёкшие).
func (s *Store) ActiveSnoozes(ctx context.Context, now time.Time) (map[string]bool, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT device_id, kind, until FROM signal_snoozes`)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return map[string]bool{}, nil
		}
		return nil, fmt.Errorf("store: отложенные сигналы: %w", err)
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var dev, kind, until string
		if err := rows.Scan(&dev, &kind, &until); err != nil {
			return nil, fmt.Errorf("store: отложенный сигнал: %w", err)
		}
		if t, err := time.Parse(time.RFC3339, until); err == nil && t.After(now) {
			out[dev+"\x00"+kind] = true
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: отложенные сигналы: %w", err)
	}
	return out, nil
}

// LastActivityAccount — последний замеченный аккаунт активности
// агента (для строки «Пользователь» карточки); пусто, если сбор
// выключен или записей нет.
func (s *Store) LastActivityAccount(ctx context.Context, agentID string) (string, error) {
	var account string
	err := s.db.QueryRowContext(ctx,
		`SELECT account FROM activity_reports WHERE agent_id = ? AND account != ''
                 ORDER BY collected_at DESC LIMIT 1`, agentID).Scan(&account)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("store: аккаунт активности: %w", err)
	}
	return account, nil
}

// HistoryEntry — запись истории изменений устройства (журнал аудита).
type HistoryEntry struct {
	At     time.Time `json:"at"`
	Actor  string    `json:"actor"`
	Action string    `json:"action"`
	Detail string    `json:"detail,omitempty"`
}

// AuditForTarget — история изменений цели (устройства) из журнала
// аудита, последние первые.
func (s *Store) AuditForTarget(ctx context.Context, target string, limit int) ([]HistoryEntry, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT ts, actor, action, detail FROM audit_log WHERE target = ?
                 ORDER BY id DESC LIMIT ?`, target, limit)
	if err != nil {
		return nil, fmt.Errorf("store: история цели: %w", err)
	}
	defer rows.Close()
	out := []HistoryEntry{}
	for rows.Next() {
		var h HistoryEntry
		var ts string
		if err := rows.Scan(&ts, &h.Actor, &h.Action, &h.Detail); err != nil {
			return nil, fmt.Errorf("store: запись истории: %w", err)
		}
		if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
			h.At = t
		}
		out = append(out, h)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: история цели: %w", err)
	}
	return out, nil
}
