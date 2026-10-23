// Тесты PKI-части хранилища (NR-007): токены регистрации
// (одноразовость, срок, только хэш в базе) и список отзыва.

package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// Токен выдаётся, расходуется один раз; повторное использование и
// просрочка — типизированные ошибки.
func TestEnrollTokenLifecycle(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()

	token, err := s.IssueEnrollToken(ctx, "owner")
	if err != nil {
		t.Fatalf("IssueEnrollToken: %v", err)
	}
	if len(token) != 64 { // 32 байта hex
		t.Fatalf("токен длиной %d, хочу 64", len(token))
	}
	if err := s.ConsumeEnrollToken(ctx, token); err != nil {
		t.Fatalf("первое использование: %v", err)
	}
	if err := s.ConsumeEnrollToken(ctx, token); !errors.Is(err, ErrTokenUsed) {
		t.Fatalf("повтор: %v, хочу ErrTokenUsed", err)
	}
	// Неизвестный токен — не найден.
	if err := s.ConsumeEnrollToken(ctx, "deadbeef"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("чужой токен: %v, хочу ErrNotFound", err)
	}
}

// Просроченный токен отвергается.
func TestEnrollTokenExpired(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	token, err := s.IssueEnrollToken(ctx, "owner")
	if err != nil {
		t.Fatalf("IssueEnrollToken: %v", err)
	}
	// Срок в базе сдвигается в прошлое напрямую (симуляция времени).
	if _, err := s.DB().Exec(
		`UPDATE enroll_tokens SET expires = ?`,
		time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("сдвиг срока: %v", err)
	}
	if err := s.ConsumeEnrollToken(ctx, token); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("просрочка: %v, хочу ErrTokenExpired", err)
	}
	// Просроченный токен остаётся нерасходованным... и всё равно
	// непригоден: повторный расход даёт ту же ошибку.
	if err := s.ConsumeEnrollToken(ctx, token); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("повторная просрочка: %v", err)
	}
}

// В базе и аудите только хэш: исходный токен не хранится.
func TestEnrollTokenHashOnly(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	token, err := s.IssueEnrollToken(ctx, "owner")
	if err != nil {
		t.Fatalf("IssueEnrollToken: %v", err)
	}
	var hashes []string
	rows, err := s.DB().Query(`SELECT hash FROM enroll_tokens`)
	if err != nil {
		t.Fatalf("чтение токенов: %v", err)
	}
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			rows.Close()
			t.Fatalf("хэш: %v", err)
		}
		hashes = append(hashes, h)
	}
	rows.Close()
	if len(hashes) != 1 {
		t.Fatalf("записей токена %d, хочу 1", len(hashes))
	}
	if strings.Contains(strings.ToLower(hashes[0]), strings.ToLower(token)) {
		t.Fatal("исходный токен найден в базе")
	}
	entries, err := auditListAll(s)
	if err != nil {
		t.Fatalf("аудит: %v", err)
	}
	for _, e := range entries {
		if strings.Contains(e.detail, token) {
			t.Fatal("исходный токен найден в аудите")
		}
	}
}

// Отзыв: серийный номер появляется в списке, повтор идемпотентен,
// запись в аудите есть.
func TestRevokeCertListedAndIdempotent(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	if err := s.RevokeCert(ctx, "123456789", "owner"); err != nil {
		t.Fatalf("RevokeCert: %v", err)
	}
	if err := s.RevokeCert(ctx, "123456789", "owner"); err != nil {
		t.Fatalf("повторный отзыв: %v", err)
	}
	revoked, err := s.ListRevoked(ctx)
	if err != nil {
		t.Fatalf("ListRevoked: %v", err)
	}
	if len(revoked) != 1 || revoked[0] != "123456789" {
		t.Fatalf("список отзыва %v, хочу [123456789]", revoked)
	}
}

// auditListAll — весь журнал для проверок утечек.
func auditListAll(s *Store) ([]auditEntry, error) {
	rows, err := s.DB().Query(`SELECT actor, action, detail FROM audit_log ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []auditEntry
	for rows.Next() {
		var e auditEntry
		if err := rows.Scan(&e.actor, &e.action, &e.detail); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

type auditEntry struct {
	actor  string
	action string
	detail string
}
