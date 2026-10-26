package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ShkodnikAI/NetAtlas/internal/model"
	"github.com/ShkodnikAI/NetAtlas/server/audit"
)

// jsonDetail — сериализация detail-поля записи аудита: данные не
// склеиваются со строкой запроса вручную.
func jsonDetail(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("store: detail: %w", err)
	}
	return string(b), nil
}

// manualKinds — типы узлов, допустимые для ручного элемента.
var manualKinds = map[string]bool{
	model.NodeKindDevice:   true,
	model.NodeKindSwitch:   true,
	model.NodeKindCloud:    true,
	model.NodeKindUnknown:  true,
	model.NodeKindInternet: true,
	model.NodeKindRouter:   true,
	model.NodeKindAP:       true,
	model.NodeKindServer:   true,
	model.NodeKindLaptop:   true,
	model.NodeKindPrinter:  true,
	model.NodeKindPhone:    true,
	model.NodeKindIot:      true,
	model.NodeKindTV:       true,
}

// AddManualDevice добавляет ручной элемент (id = manual:<uuid>):
// запись помечается manual=1, verified=0. Возвращает идентификатор.
func (s *Store) AddManualDevice(ctx context.Context, kind, label, actor string) (string, error) {
	if !manualKinds[kind] {
		return "", fmt.Errorf("store: недопустимый тип элемента %q", kind)
	}
	label = strings.TrimSpace(label)
	if len(label) > model.MaxNameLen {
		return "", fmt.Errorf("store: имя длиннее %d символов", model.MaxNameLen)
	}
	id, err := newManualID()
	if err != nil {
		return "", err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", fmt.Errorf("store: транзакция: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `INSERT INTO devices
                (id, kind, class, label, manual, verified, first_seen, last_seen)
                VALUES (?, ?, 'unknown', ?, 1, 0, ?, ?)`,
		id, kind, label, now, now); err != nil {
		return "", fmt.Errorf("store: ручной элемент: %w", err)
	}
	if _, err := audit.Append(ctx, tx, audit.Entry{
		Actor: actor, Action: "add_device", Target: id, Result: "ok",
		Detail: string(mustJSON(map[string]string{"kind": kind})),
	}); err != nil {
		return "", err
	}
	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("store: фиксация: %w", err)
	}
	return id, nil
}

// Update — правка устройства: поля-указатели, nil — не менять.
// Kind — ручной выбор типа владельцем (NR-032 п.1): запись
// помечается kind_manual = 1 и перекрывает автоматический вывод
// классификатора при последующих сканах.
type Update struct {
	Name     *string
	Class    *model.Class
	Kind     *string
	Verified *bool
}

// UpdateDevice меняет ручное имя, класс и признак проверки.
func (s *Store) UpdateDevice(ctx context.Context, id string, upd Update, actor string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: транзакция: %w", err)
	}
	defer tx.Rollback()
	var exists int
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM devices WHERE id = ?`, id).Scan(&exists); err != nil {
		return fmt.Errorf("store: устройство %s: %w", id, err)
	}
	if exists == 0 {
		return ErrNotFound
	}
	if upd.Name != nil {
		name := strings.TrimSpace(*upd.Name)
		if len(name) > model.MaxNameLen {
			return fmt.Errorf("store: имя длиннее %d символов", model.MaxNameLen)
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE devices SET label = ? WHERE id = ?`, name, id); err != nil {
			return fmt.Errorf("store: имя устройства %s: %w", id, err)
		}
	}
	if upd.Class != nil {
		if !upd.Class.Valid() {
			return fmt.Errorf("store: недопустимый класс %q", string(*upd.Class))
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE devices SET class = ? WHERE id = ?`, string(*upd.Class), id); err != nil {
			return fmt.Errorf("store: класс устройства %s: %w", id, err)
		}
		// Смена класса закрывает открытые оповещения устройства.
		if _, err := closeAlerts(ctx, tx, id, time.Now()); err != nil {
			return err
		}
	}
	if upd.Kind != nil {
		kind := strings.TrimSpace(*upd.Kind)
		if !manualKinds[kind] {
			return fmt.Errorf("store: недопустимый тип устройства %q", kind)
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE devices SET kind = ?, kind_manual = 1 WHERE id = ?`, kind, id); err != nil {
			return fmt.Errorf("store: тип устройства %s: %w", id, err)
		}
	}
	if upd.Verified != nil {
		v := 0
		if *upd.Verified {
			v = 1
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE devices SET verified = ? WHERE id = ?`, v, id); err != nil {
			return fmt.Errorf("store: признак проверки устройства %s: %w", id, err)
		}
	}
	detail, err := jsonDetail(upd)
	if err != nil {
		return err
	}
	if _, err := audit.Append(ctx, tx, audit.Entry{
		Actor: actor, Action: "update_device", Target: id, Result: "ok", Detail: detail,
	}); err != nil {
		return err
	}
	return tx.Commit()
}

// DeleteManualDevice удаляет ручной элемент вместе с его данными и
// связями; найденное сканером устройство удалить нельзя.
func (s *Store) DeleteManualDevice(ctx context.Context, id, actor string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: транзакция: %w", err)
	}
	defer tx.Rollback()
	var manual int
	err = tx.QueryRowContext(ctx,
		`SELECT manual FROM devices WHERE id = ?`, id).Scan(&manual)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("store: устройство %s: %w", id, err)
	}
	if manual == 0 {
		return fmt.Errorf("store: устройство %s: %w", id, ErrNotManual)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM devices WHERE id = ?`, id); err != nil {
		return fmt.Errorf("store: удаление устройства %s: %w", id, err)
	}
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM links WHERE a = ? OR b = ?`, id, id); err != nil {
		return fmt.Errorf("store: удаление связей устройства %s: %w", id, err)
	}
	if _, err := audit.Append(ctx, tx, audit.Entry{
		Actor: actor, Action: "delete_device", Target: id, Result: "ok",
	}); err != nil {
		return err
	}
	return tx.Commit()
}

// AddManualLink добавляет ручную связь между двумя существующими
// узлами графа (устройства либо системные узлы ip:/cloud:).
func (s *Store) AddManualLink(ctx context.Context, a, aPort, b, bPort, actor string) (string, error) {
	a, aPort, b, bPort = strings.TrimSpace(a), strings.TrimSpace(aPort), strings.TrimSpace(b), strings.TrimSpace(bPort)
	if a == "" || b == "" || a == b {
		return "", fmt.Errorf("store: связь требует двух разных узлов")
	}
	if b < a {
		a, aPort, b, bPort = b, bPort, a, aPort
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", fmt.Errorf("store: транзакция: %w", err)
	}
	defer tx.Rollback()
	for _, end := range []string{a, b} {
		var known int
		if err := tx.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM devices WHERE id = ?`, end).Scan(&known); err != nil {
			return "", fmt.Errorf("store: узел %s: %w", end, err)
		}
		if known == 0 && !strings.HasPrefix(end, "ip:") && !strings.HasPrefix(end, "cloud:") {
			return "", fmt.Errorf("store: узел %s: %w", end, ErrNotFound)
		}
	}
	id, err := newManualID()
	if err != nil {
		return "", err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO links
                (id, a, a_port, b, b_port, source, manual, verified)
                VALUES (?, ?, ?, ?, ?, 'manual', 1, 0)
                ON CONFLICT(a, a_port, b, b_port) DO NOTHING`,
		id, a, aPort, b, bPort); err != nil {
		return "", fmt.Errorf("store: ручная связь: %w", err)
	}
	// Если связь уже существовала (найдена сканером), она не стала
	// ручной: вернуть её фактический идентификатор.
	var real string
	if err := tx.QueryRowContext(ctx,
		`SELECT id FROM links WHERE a = ? AND a_port = ? AND b = ? AND b_port = ?`,
		a, aPort, b, bPort).Scan(&real); err != nil {
		return "", fmt.Errorf("store: ручная связь: %w", err)
	}
	if _, err := audit.Append(ctx, tx, audit.Entry{
		Actor: actor, Action: "add_link", Target: real, Result: "ok",
		Detail: string(mustJSON(map[string]string{"a": a, "b": b})),
	}); err != nil {
		return "", err
	}
	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("store: фиксация: %w", err)
	}
	return real, nil
}

// DeleteManualLink удаляет ручную связь; найденную сканером удалить
// нельзя.
func (s *Store) DeleteManualLink(ctx context.Context, id, actor string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: транзакция: %w", err)
	}
	defer tx.Rollback()
	var manual int
	err = tx.QueryRowContext(ctx,
		`SELECT manual FROM links WHERE id = ?`, id).Scan(&manual)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("store: связь %s: %w", id, err)
	}
	if manual == 0 {
		return fmt.Errorf("store: связь %s: %w", id, ErrNotManual)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM links WHERE id = ?`, id); err != nil {
		return fmt.Errorf("store: удаление связи %s: %w", id, err)
	}
	if _, err := audit.Append(ctx, tx, audit.Entry{
		Actor: actor, Action: "delete_link", Target: id, Result: "ok",
	}); err != nil {
		return err
	}
	return tx.Commit()
}

// mustJSON — сериализация без ошибки: данные — простые строки.
func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		return []byte("{}")
	}
	return b
}

// newManualID — ручной идентификатор manual:<uuid4> из crypto/rand.
func newManualID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("store: uuid: %w", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40 // версия 4
	b[8] = (b[8] & 0x3f) | 0x80 // вариант RFC 4122
	h := fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
	return "manual:" + h, nil
}
