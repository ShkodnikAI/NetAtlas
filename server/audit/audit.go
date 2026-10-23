// Package audit — журнал аудита, в который можно только дописывать.
//
// Каждая запись хранит prev_hash и hash: hash — SHA-256 от предыдущего
// хэша и полей записи, поэтому цепочка обнаруживает и подмену поля
// существующей записи, и разрыв (удаление или вставку между
// существующими). Правка и удаление запрещены триггерами SQLite
// (миграция 0001 в server/store); в пакете нет методов изменения.
//
// Сеть пакет не касается; секреты в записи не допускаются на уровне
// вызывающего кода (имена переменных окружения допустимы, значения —
// никогда).
package audit

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Entry — одна запись журнала аудита.
type Entry struct {
	ID       int64     `json:"id"`
	Ts       time.Time `json:"ts"`
	Actor    string    `json:"actor"`
	Action   string    `json:"action"`
	Target   string    `json:"target"`
	Result   string    `json:"result"`
	Detail   string    `json:"detail,omitempty"`
	PrevHash string    `json:"prev_hash"`
	Hash     string    `json:"hash"`
}

// DBTX — минимальный интерфейс исполнения запросов: достаточен и для
// *sql.DB, и для *sql.Tx. Append работает внутри транзакции
// вызывающего (store), List и Verify — на открытой базе.
type DBTX interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// DetailLimit — максимальный размер поля detail (защита от раздувания
// журнала): строка длиннее отбрасывается с ошибкой.
const DetailLimit = 8192

// Append дописывает запись в журнал в транзакции вызывающего: ts
// заполняется текущим временем, если пустое; prev_hash — хэш последней
// записи; hash — SHA-256 от предыдущего хэша и полей. Возвращает
// запись с заполненными ts, PrevHash и Hash.
func Append(ctx context.Context, tx DBTX, e Entry) (Entry, error) {
	if strings.TrimSpace(e.Actor) == "" {
		return Entry{}, fmt.Errorf("audit: запись без актора")
	}
	if strings.TrimSpace(e.Action) == "" {
		return Entry{}, fmt.Errorf("audit: запись без действия")
	}
	if len(e.Detail) > DetailLimit {
		return Entry{}, fmt.Errorf("audit: detail длиннее %d байт", DetailLimit)
	}
	if e.Ts.IsZero() {
		e.Ts = time.Now()
	}
	var prev string
	err := tx.QueryRowContext(ctx,
		`SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1`).Scan(&prev)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		prev = "" // первая запись: genesis
	case err != nil:
		return Entry{}, fmt.Errorf("audit: предыдущий хэш: %w", err)
	}
	e.PrevHash = prev
	e.Hash = chainHash(e)
	ts := e.Ts.UTC().Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO audit_log (ts, actor, action, target, result, detail, prev_hash, hash)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		ts, e.Actor, e.Action, e.Target, e.Result, e.Detail, e.PrevHash, e.Hash); err != nil {
		return Entry{}, fmt.Errorf("audit: вставка: %w", err)
	}
	return e, nil
}

// List возвращает последние записи журнала (по убыванию id): не
// больше limit (0 — 50, максимум 1000), только с id меньше before
// (0 — без ограничения).
func List(ctx context.Context, db DBTX, limit int, before int64) ([]Entry, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 1000 {
		limit = 1000
	}
	q := `SELECT id, ts, actor, action, target, result, detail, prev_hash, hash
	      FROM audit_log`
	args := []any{}
	if before > 0 {
		q += ` WHERE id < ?`
		args = append(args, before)
	}
	q += ` ORDER BY id DESC LIMIT ?`
	args = append(args, limit)

	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("audit: список: %w", err)
	}
	defer rows.Close()
	out := []Entry{}
	for rows.Next() {
		var e Entry
		var ts string
		if err := rows.Scan(&e.ID, &ts, &e.Actor, &e.Action, &e.Target,
			&e.Result, &e.Detail, &e.PrevHash, &e.Hash); err != nil {
			return nil, fmt.Errorf("audit: чтение: %w", err)
		}
		if e.Ts, err = time.Parse(time.RFC3339Nano, ts); err != nil {
			return nil, fmt.Errorf("audit: время записи %d: %w", e.ID, err)
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("audit: обход: %w", err)
	}
	return out, nil
}

// Verify проходит цепочку от начала до конца и возвращает ошибку при
// разрыве (prev_hash записи не равен хэшу предыдущей), подмене полей
// (пересчитанный hash не равен сохранённому) или записи без
// предыдущего хэша genesis.
func Verify(ctx context.Context, db DBTX) error {
	rows, err := db.QueryContext(ctx,
		`SELECT id, ts, actor, action, target, result, detail, prev_hash, hash
		 FROM audit_log ORDER BY id ASC`)
	if err != nil {
		return fmt.Errorf("audit: чтение цепочки: %w", err)
	}
	defer rows.Close()

	prev := "" // genesis: первая запись ссылается на пустой хэш
	n := 0
	for rows.Next() {
		var e Entry
		var ts string
		if err := rows.Scan(&e.ID, &ts, &e.Actor, &e.Action, &e.Target,
			&e.Result, &e.Detail, &e.PrevHash, &e.Hash); err != nil {
			return fmt.Errorf("audit: чтение записи: %w", err)
		}
		n++
		if e.Ts, err = time.Parse(time.RFC3339Nano, ts); err != nil {
			return fmt.Errorf("audit: время записи %d: %w", e.ID, err)
		}
		if e.PrevHash != prev {
			return fmt.Errorf("audit: разрыв цепочки на записи %d: prev_hash %q, ожидался %q",
				e.ID, e.PrevHash, prev)
		}
		if want := chainHash(e); want != e.Hash {
			return fmt.Errorf("audit: подмена записи %d: hash %q, ожидался %q",
				e.ID, e.Hash, want)
		}
		prev = e.Hash
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("audit: обход цепочки: %w", err)
	}
	return nil
}

// chainHash — SHA-256 от предыдущего хэша и полей записи, разделённых
// управляющим байтом. Поля берутся в канонической форме: ts в UTC
// (RFC 3339 с наносекундами).
func chainHash(e Entry) string {
	ts := e.Ts.UTC().Format(time.RFC3339Nano)
	h := sha256.New()
	for _, part := range []string{e.PrevHash, ts, e.Actor, e.Action, e.Target, e.Result, e.Detail} {
		h.Write([]byte(part))
		h.Write([]byte{0x1f})
	}
	return hex.EncodeToString(h.Sum(nil))
}
