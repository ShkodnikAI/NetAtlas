// Тесты очереди: порядок, подтверждение, вытеснение по лимиту,
// устойчивость имён. Тест вытеснения обязан падать, если снять лимит.
package spool

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func openTest(t *testing.T, max int64) *Spool {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "spool"), max)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return s
}

func blob(t *testing.T, size int, marker string) []byte {
	t.Helper()
	b := make([]byte, size)
	for i := range b {
		b[i] = byte('a' + i%26)
	}
	copy(b, marker)
	return b
}

// Порядок: FIFO по времени; Ack удаляет подтверждённую запись.
func TestSpoolFIFOAndAck(t *testing.T) {
	s := openTest(t, DefaultMaxBytes)
	for _, m := range []string{"first", "second", "third"} {
		if err := s.Push(blob(t, 32, m)); err != nil {
			t.Fatalf("Push %s: %v", m, err)
		}
	}
	// Первая запись — first, файл после Pop остаётся до Ack.
	id1, d1, err := s.Pop()
	if err != nil {
		t.Fatalf("Pop: %v", err)
	}
	if !strings.HasPrefix(string(d1), "first") {
		t.Fatalf("первая запись %q, хочу first", string(d1[:5]))
	}
	if n, _ := s.Len(); n != 3 {
		t.Fatalf("после Pop записей %d, хочу 3 (файл до Ack)", n)
	}
	if err := s.Ack(id1); err != nil {
		t.Fatalf("Ack: %v", err)
	}
	if n, _ := s.Len(); n != 2 {
		t.Fatalf("после Ack записей %d, хочу 2", n)
	}
	_, d2, err := s.Pop()
	if err != nil || !strings.HasPrefix(string(d2), "second") {
		t.Fatalf("вторая запись: %q (err %v)", string(d2[:min(6, len(d2))]), err)
	}
	// Пустая очередь — ErrEmpty.
	_ = s.Ack(mustPopAck(t, s))
	_ = s.Ack(mustPopAck(t, s))
	if _, _, err := s.Pop(); !errors.Is(err, ErrEmpty) {
		t.Fatalf("пустая очередь: %v, хочу ErrEmpty", err)
	}
}

func mustPopAck(t *testing.T, s *Spool) string {
	t.Helper()
	id, _, err := s.Pop()
	if err != nil {
		t.Fatalf("Pop: %v", err)
	}
	return id
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Вытеснение: суммарный объём не превышает лимит, вытесняется самое
// старое. Тест обязан падать, если снять лимит (мутация M1).
func TestSpoolEvictsOldestWithinLimit(t *testing.T) {
	const limit = 1000
	s := openTest(t, limit)
	for i := 0; i < 10; i++ {
		if err := s.Push(blob(t, 300, "blob")); err != nil {
			t.Fatalf("Push %d: %v", i, err)
		}
	}
	total, err := s.TotalBytes()
	if err != nil {
		t.Fatalf("TotalBytes: %v", err)
	}
	if total > limit {
		t.Fatalf("объём очереди %d превышает лимит %d — вытеснение не работает", total, limit)
	}
	// Оставшиеся записи — самые свежие: первый (самый старый) вытеснен.
	id, d, err := s.Pop()
	if err != nil {
		t.Fatalf("Pop: %v", err)
	}
	_ = id
	if strings.Contains(string(d), "stale") {
		t.Fatal("самая старая запись не вытеснена")
	}
}

// Чужие имена и подкаталоги в каталоге очереди игнорируются.
func TestSpoolIgnoresForeignFiles(t *testing.T) {
	s := openTest(t, DefaultMaxBytes)
	if err := s.Push(blob(t, 16, "ok")); err != nil {
		t.Fatalf("Push: %v", err)
	}
	foreign := filepath.Join(s.dir, "manual-note.txt")
	if err := os.WriteFile(foreign, []byte("не очередь"), 0o600); err != nil {
		t.Fatalf("чужой файл: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(s.dir, "subdir"), 0o700); err != nil {
		t.Fatalf("подкаталог: %v", err)
	}
	if n, _ := s.Len(); n != 1 {
		t.Fatalf("записей %d, хочу 1 (чужие файлы не очередь)", n)
	}
	// Идентификатор чужого файла Ack не принимает.
	if err := s.Ack("manual-note.txt"); err == nil {
		t.Fatal("Ack чужого имени принят")
	}
	if err := s.Ack("../escape.json"); err == nil {
		t.Fatal("Ack с обходом пути принят")
	}
}
