// PKI-часть хранилища (NR-007): токены регистрации агентов
// (одноразовые, в базе только хэш) и список отзыва сертификатов.
// Изменяющие операции пишут аудит в своей транзакции.
package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/ShkodnikAI/NetAtlas/server/audit"
)

// EnrollTokenTTL — срок жизни токена регистрации.
const EnrollTokenTTL = time.Hour

// Ошибки-сентинелы токена регистрации: API отображает их в коды.
var (
	// ErrTokenUsed — токен уже использован (одноразовость).
	ErrTokenUsed = fmt.Errorf("store: токен регистрации уже использован")
	// ErrTokenExpired — срок жизни токена истёк.
	ErrTokenExpired = fmt.Errorf("store: срок токена регистрации истёк")
)

// NewEnrollToken генерирует случайный токен регистрации (32 байта,
// hex): показывается владельцу один раз, в базе остаётся только хэш.
func NewEnrollToken() (string, []byte, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, fmt.Errorf("store: токен регистрации: %w", err)
	}
	token := hex.EncodeToString(raw)
	// Хэш считается от напечатанной строки: consume сравнивает то,
	// что владелец вставил в запрос.
	sum := sha256.Sum256([]byte(token))
	return token, sum[:], nil
}

// IssueEnrollToken выдаёт токен регистрации: сам токен возвращается
// один раз, в базе и аудите — только хэш. Аудит пишется в транзакции
// с созданием записи.
func (s *Store) IssueEnrollToken(ctx context.Context, actor string) (string, error) {
	token, hash, err := NewEnrollToken()
	if err != nil {
		return "", err
	}
	now := time.Now()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", fmt.Errorf("store: транзакция токена: %w", err)
	}
	defer tx.Rollback()
	detail, err := json.Marshal(map[string]any{
		"token_hash": hex.EncodeToString(hash),
		"expires":    now.Add(EnrollTokenTTL).UTC().Format(time.RFC3339Nano),
	})
	if err != nil {
		return "", fmt.Errorf("store: сводка токена: %w", err)
	}
	if _, err := audit.Append(ctx, tx, audit.Entry{
		Actor: actor, Action: "issue_enroll_token", Target: "enroll_token",
		Result: "ok", Detail: string(detail),
	}); err != nil {
		return "", err
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO enroll_tokens (hash, created, expires) VALUES (?, ?, ?)`,
		hex.EncodeToString(hash), now.UTC().Format(time.RFC3339Nano),
		now.Add(EnrollTokenTTL).UTC().Format(time.RFC3339Nano)); err != nil {
		return "", fmt.Errorf("store: запись токена: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("store: фиксация токена: %w", err)
	}
	return token, nil
}

// ConsumeEnrollToken расходует токен регистрации: одноразовость и
// срок проверяются атомарно. Поиск идёт по хэшу токена; исходный
// токен в базе не хранится. Повторное использование и просрочка —
// типизированные ошибки.
func (s *Store) ConsumeEnrollToken(ctx context.Context, token string) error {
	if token == "" {
		return ErrNotFound
	}
	sum := sha256.Sum256([]byte(token))
	hash := hex.EncodeToString(sum[:])
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: транзакция токена: %w", err)
	}
	defer tx.Rollback()
	var expires, usedAt string
	err = tx.QueryRowContext(ctx,
		`SELECT expires, used_at FROM enroll_tokens WHERE hash = ?`, hash).Scan(&expires, &usedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("store: токен: %w", err)
	}
	if usedAt != "" {
		return ErrTokenUsed
	}
	exp, err := time.Parse(time.RFC3339Nano, expires)
	if err != nil {
		return fmt.Errorf("store: срок токена: %w", err)
	}
	if time.Now().After(exp) {
		return ErrTokenExpired
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE enroll_tokens SET used_at = ? WHERE hash = ?`,
		time.Now().UTC().Format(time.RFC3339Nano), hash); err != nil {
		return fmt.Errorf("store: расход токена: %w", err)
	}
	if _, err := audit.Append(ctx, tx, audit.Entry{
		Actor: "agent-api", Action: "consume_enroll_token", Target: "enroll_token",
		Result: "ok", Detail: hash,
	}); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: фиксация токена: %w", err)
	}
	return nil
}

// TokenMatchesHash — сравнение хэша токена за постоянное время
// (для вызывающих сторон, которые сверяют токен сами).
func TokenMatchesHash(token, hashHex string) bool {
	sum := sha256.Sum256([]byte(token))
	want, err := hex.DecodeString(hashHex)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(sum[:], want) == 1
}

// RevokeCert отзывает сертификат по серийному номеру (десятичная
// строка): запись идемпотентна, аудит — в той же транзакции.
func (s *Store) RevokeCert(ctx context.Context, serial, actor string) error {
	if serial == "" {
		return fmt.Errorf("store: серийный номер пуст")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: транзакция отзыва: %w", err)
	}
	defer tx.Rollback()
	detail, err := json.Marshal(map[string]string{"serial": serial})
	if err != nil {
		return fmt.Errorf("store: сводка отзыва: %w", err)
	}
	if _, err := audit.Append(ctx, tx, audit.Entry{
		Actor: actor, Action: "revoke_cert", Target: "cert:" + serial,
		Result: "ok", Detail: string(detail),
	}); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT OR IGNORE INTO revoked_certs (serial, revoked_at, actor) VALUES (?, ?, ?)`,
		serial, time.Now().UTC().Format(time.RFC3339Nano), actor); err != nil {
		return fmt.Errorf("store: запись отзыва: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: фиксация отзыва: %w", err)
	}
	return nil
}

// ListRevoked возвращает серийные номера отозванных сертификатов
// (для проверки на handshake).
func (s *Store) ListRevoked(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT serial FROM revoked_certs ORDER BY serial`)
	if err != nil {
		return nil, fmt.Errorf("store: список отзыва: %w", err)
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var serial string
		if err := rows.Scan(&serial); err != nil {
			return nil, fmt.Errorf("store: серийный номер: %w", err)
		}
		out = append(out, serial)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: список отзыва: %w", err)
	}
	return out, nil
}
