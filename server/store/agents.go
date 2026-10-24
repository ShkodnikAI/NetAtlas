// Агенты (NR-024): регистрация по одноразовому токену, состояния,
// инвентарь, привязка к устройствам карты по MAC. Изменяющие операции
// пишут аудит в своей транзакции.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ShkodnikAI/NetAtlas/internal/model"
	"github.com/ShkodnikAI/NetAtlas/server/audit"
)

// Agent — зарегистрированный агент.
type Agent struct {
	ID         string    `json:"id"`
	Hostname   string    `json:"hostname"`
	EnrolledAt time.Time `json:"enrolled_at"`
	LastSeen   time.Time `json:"last_seen,omitempty"`
	CertSerial string    `json:"cert_serial"`
	Status     string    `json:"status"`
	MACList    []string  `json:"mac_list"`
}

// ErrAgentRevoked — агент уже отозван; повторный отзыв — конфликт.
var ErrAgentRevoked = errors.New("store: агент отозван")

// MaxAgentMACs — предел MAC-адресов в списке агента.
const MaxAgentMACs = 64

// NormalizeAgentMACs приводит список MAC к каноническому виду
// (aa:bb:cc:dd:ee:ff) и убирает повторы; мусорные значения
// отбрасываются, а не блокируют регистрацию. Список ограничен
// MaxAgentMACs.
func NormalizeAgentMACs(macs []string) []string {
	norm := make([]string, 0, len(macs))
	for _, m := range macs {
		n, err := model.NormalizeMAC(m)
		if err != nil {
			continue
		}
		if !contains(norm, n) {
			norm = append(norm, n)
		}
		if len(norm) >= MaxAgentMACs {
			break
		}
	}
	return norm
}

// UpsertAgent регистрирует агента: CN сертификата — личность, серийный
// номер и нормализованный MAC-список сохраняются. Повторная
// регистрация того же CN обновляет данные (новый сертификат после
// перевыпуска возвращает агента в active). Аудит — в той же
// транзакции.
func (s *Store) UpsertAgent(ctx context.Context, id, hostname, certSerial string, macs []string, actor string) error {
	if !strings.HasPrefix(id, "agent:") {
		return fmt.Errorf("store: id агента %q без префикса agent:", id)
	}
	if len(hostname) > 255 {
		hostname = hostname[:255]
	}
	if macs == nil {
		macs = []string{}
	}
	norm := NormalizeAgentMACs(macs)
	macJSON, err := json.Marshal(norm)
	if err != nil {
		return fmt.Errorf("store: mac-список агента: %w", err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: транзакция агента: %w", err)
	}
	defer tx.Rollback()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, `INSERT INTO agents
		(id, hostname, enrolled_at, last_seen, cert_serial, status, mac_list)
		VALUES (?, ?, ?, ?, ?, 'active', ?)
		ON CONFLICT(id) DO UPDATE SET
			hostname = excluded.hostname,
			cert_serial = excluded.cert_serial,
			status = 'active',
			mac_list = excluded.mac_list`,
		id, hostname, now, now, certSerial, string(macJSON)); err != nil {
		return fmt.Errorf("store: агент %s: %w", id, err)
	}
	detail, err := json.Marshal(map[string]any{"agent": id, "serial": certSerial, "macs": len(norm)})
	if err != nil {
		return fmt.Errorf("store: сводка агента: %w", err)
	}
	if _, err := audit.Append(ctx, tx, audit.Entry{
		Actor: actor, Action: "agent_enroll", Target: id, Result: "ok", Detail: string(detail),
	}); err != nil {
		return err
	}
	return tx.Commit()
}

// AgentCheckin отмечает выход агента на связь. Неизвестный агент —
// ErrNotFound. Успешный heartbeat в журнал аудита не пишется: при
// частоте опроса и числе агентов он разорвал бы цепочку своей
// частотой; отказы (неизвестный/отозванный агент) пишет API.
func (s *Store) AgentCheckin(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE agents SET last_seen = ? WHERE id = ?`,
		time.Now().UTC().Format(time.RFC3339Nano), id)
	if err != nil {
		return fmt.Errorf("store: checkin агента: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// SaveInventory сохраняет порцию инвентаря (тело запроса как есть:
// конверт с kind, schema_ver, collected_at и payload) и пишет аудит.
// Неизвестный агент — ErrNotFound (внешний ключ).
func (s *Store) SaveInventory(ctx context.Context, agentID, kind string, schemaVer int, collectedAt time.Time, raw []byte) error {
	if collectedAt.IsZero() {
		collectedAt = time.Now()
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: транзакция инвентаря: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO agent_inventory (agent_id, collected_at, kind, json, schema_ver)
		 VALUES (?, ?, ?, ?, ?)`,
		agentID, collectedAt.UTC().Format(time.RFC3339Nano), kind, string(raw), schemaVer); err != nil {
		return fmt.Errorf("store: инвентарь %s: %w", agentID, err)
	}
	detail, err := json.Marshal(map[string]any{"agent": agentID, "kind": kind, "bytes": len(raw), "schema": schemaVer})
	if err != nil {
		return fmt.Errorf("store: сводка инвентаря: %w", err)
	}
	if _, err := audit.Append(ctx, tx, audit.Entry{
		Actor: agentID, Action: "agent_inventory", Target: agentID, Result: "ok", Detail: string(detail),
	}); err != nil {
		return err
	}
	return tx.Commit()
}

// ListAgents возвращает агентов (новые регистрации сверху).
func (s *Store) ListAgents(ctx context.Context) ([]Agent, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, hostname, enrolled_at, last_seen, cert_serial, status, mac_list
		 FROM agents ORDER BY enrolled_at DESC, id`)
	if err != nil {
		return nil, fmt.Errorf("store: список агентов: %w", err)
	}
	defer rows.Close()
	out := []Agent{}
	for rows.Next() {
		a, err := scanAgent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// AgentByID — карточка агента; не найден — ErrNotFound.
func (s *Store) AgentByID(ctx context.Context, id string) (Agent, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, hostname, enrolled_at, last_seen, cert_serial, status, mac_list
		 FROM agents WHERE id = ?`, id)
	a, err := scanAgent(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Agent{}, ErrNotFound
	}
	return a, err
}

// InventoryRow — последняя порция инвентаря агента.
type InventoryRow struct {
	Kind        string    `json:"kind"`
	SchemaVer   int       `json:"schema_ver"`
	CollectedAt time.Time `json:"collected_at"`
	JSON        string    `json:"json"`
}

// LatestInventory — последняя порция инвентаря агента (для
// GET /api/agents/{id}/inventory). Нет ни агента, ни порций —
// ErrNotFound.
func (s *Store) LatestInventory(ctx context.Context, agentID string) (InventoryRow, error) {
	var row InventoryRow
	var collected string
	err := s.db.QueryRowContext(ctx,
		`SELECT kind, schema_ver, collected_at, json
		 FROM agent_inventory WHERE agent_id = ? ORDER BY id DESC LIMIT 1`, agentID).
		Scan(&row.Kind, &row.SchemaVer, &collected, &row.JSON)
	if errors.Is(err, sql.ErrNoRows) {
		return InventoryRow{}, ErrNotFound
	}
	if err != nil {
		return InventoryRow{}, fmt.Errorf("store: инвентарь %s: %w", agentID, err)
	}
	row.CollectedAt, err = time.Parse(time.RFC3339Nano, collected)
	if err != nil {
		return InventoryRow{}, fmt.Errorf("store: время инвентаря %s: %w", agentID, err)
	}
	return row, nil
}

// ListRevokedAgents — идентификаторы отозванных агентов: список
// поднимается при handshake (кэш не дольше 10 секунд).
func (s *Store) ListRevokedAgents(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id FROM agents WHERE status = 'revoked' ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("store: список отозванных агентов: %w", err)
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("store: идентификатор агента: %w", err)
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// RevokeAgent отзывает агента: статус revoked, аудит в той же
// транзакции. Уже отозванный — ErrAgentRevoked, не найденный —
// ErrNotFound.
func (s *Store) RevokeAgent(ctx context.Context, id, actor string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: транзакция отзыва: %w", err)
	}
	defer tx.Rollback()
	var status string
	err = tx.QueryRowContext(ctx, `SELECT status FROM agents WHERE id = ?`, id).Scan(&status)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("store: агент %s: %w", id, err)
	}
	if status == "revoked" {
		return ErrAgentRevoked
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE agents SET status = 'revoked' WHERE id = ?`, id); err != nil {
		return fmt.Errorf("store: отзыв агента %s: %w", id, err)
	}
	if _, err := audit.Append(ctx, tx, audit.Entry{
		Actor: actor, Action: "agent_revoke", Target: id, Result: "ok",
	}); err != nil {
		return err
	}
	return tx.Commit()
}

// IsAgentRevoked — свежий статус агента без кэша: страховка на
// маршрутах на случай окна кэша handshake.
func (s *Store) IsAgentRevoked(ctx context.Context, id string) (bool, error) {
	var status string
	err := s.db.QueryRowContext(ctx, `SELECT status FROM agents WHERE id = ?`, id).Scan(&status)
	if errors.Is(err, sql.ErrNoRows) {
		return false, ErrNotFound
	}
	if err != nil {
		return false, fmt.Errorf("store: статус агента: %w", err)
	}
	return status == "revoked", nil
}

// LinkAgentMACs привязывает агента к устройствам карты: устройство с
// ID=MAC получает класс managed (создаётся, если его нет), ручные
// поля (label, hostname, vendor, ssid, manual) не затираются, аудит —
// в той же транзакции.
func (s *Store) LinkAgentMACs(ctx context.Context, agentID string, macs []string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: транзакция привязки: %w", err)
	}
	defer tx.Rollback()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	linked := 0
	for _, m := range NormalizeAgentMACs(macs) {
		if _, err := tx.ExecContext(ctx, `INSERT INTO devices
			(id, kind, class, label, hostname, vendor, ssid, manual, verified, first_seen, last_seen)
			VALUES (?, 'device', 'managed', '', '', '', '', 0, 0, ?, ?)
			ON CONFLICT(id) DO UPDATE SET class = 'managed', last_seen = excluded.last_seen`,
			m, now, now); err != nil {
			return fmt.Errorf("store: устройство %s: %w", m, err)
		}
		linked++
	}
	detail, err := json.Marshal(map[string]any{"agent": agentID, "linked": linked})
	if err != nil {
		return fmt.Errorf("store: сводка привязки: %w", err)
	}
	if _, err := audit.Append(ctx, tx, audit.Entry{
		Actor: agentID, Action: "agent_link_macs", Target: agentID, Result: "ok", Detail: string(detail),
	}); err != nil {
		return err
	}
	return tx.Commit()
}

// agentRow — сканер строки агента для Query и QueryRow.
type agentRow interface {
	Scan(dest ...any) error
}

func scanAgent(r agentRow) (Agent, error) {
	var a Agent
	var enrolled, lastSeen, macJSON string
	if err := r.Scan(&a.ID, &a.Hostname, &enrolled, &lastSeen, &a.CertSerial, &a.Status, &macJSON); err != nil {
		return Agent{}, err
	}
	var err error
	a.EnrolledAt, err = time.Parse(time.RFC3339Nano, enrolled)
	if err != nil {
		return Agent{}, fmt.Errorf("store: время регистрации агента: %w", err)
	}
	if lastSeen != "" {
		a.LastSeen, err = time.Parse(time.RFC3339Nano, lastSeen)
		if err != nil {
			return Agent{}, fmt.Errorf("store: время выхода агента: %w", err)
		}
	}
	a.MACList = []string{}
	if err := json.Unmarshal([]byte(macJSON), &a.MACList); err != nil {
		return Agent{}, fmt.Errorf("store: mac-список агента %s: %w", a.ID, err)
	}
	return a, nil
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
