// Негативные тесты проверки заданий на агенте (NR-007): все отказы
// из наряда — без подписи, чужой ключ, изменённое содержимое,
// изменённая цель, просрочка, ещё не действует, повтор и повтор после
// «перезапуска».

package verify

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ShkodnikAI/NetAtlas/server/signing"
)

type fixture struct {
	env     signing.Envelope
	priv    ed25519.PrivateKey
	pub     ed25519.PublicKey
	content []byte
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	content := []byte("задание: опроси подсеть")
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("nonce: %v", err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ключ: %v", err)
	}
	now := time.Now()
	return fixture{
		env: signing.Envelope{
			JobID:         "job-42",
			AgentID:       "agent-1",
			Kind:          "inventory",
			ContentSHA256: signing.HashContent(content),
			IssuedAt:      now.Add(-time.Minute),
			ExpiresAt:     now.Add(time.Hour),
			Nonce:         nonce,
		},
		priv:    priv,
		pub:     pub,
		content: content,
	}
}

func (f fixture) signed(t *testing.T) signing.SignedJob {
	t.Helper()
	sj, err := signing.Sign(f.env, f.priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return sj
}

// Валидное задание проходит проверку и попадает в журнал seen.
func TestVerifyAccepts(t *testing.T) {
	f := newFixture(t)
	sj := f.signed(t)
	sj.Content = f.content
	if err := Verify(sj, f.pub, "agent-1", time.Now(), nil); err != nil {
		t.Fatalf("валидное задание отвергнуто: %v", err)
	}
}

// Задание без подписи отвергается раньше остальных проверок.
func TestVerifyNoSignature(t *testing.T) {
	f := newFixture(t)
	sj := f.signed(t)
	sj.Signature = nil
	if err := Verify(sj, f.pub, "agent-1", time.Now(), nil); !errors.Is(err, ErrNoSignature) {
		t.Fatalf("ошибка %v, хочу ErrNoSignature", err)
	}
}

// Чужой ключ подписи отвергается.
func TestVerifyForeignKey(t *testing.T) {
	f := newFixture(t)
	sj := f.signed(t)
	otherPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ключ: %v", err)
	}
	if err := Verify(sj, otherPub, "agent-1", time.Now(), nil); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("ошибка %v, хочу ErrBadSignature", err)
	}
}

// Изменённый байт содержимого ловится по хэшу.
func TestVerifyContentTampered(t *testing.T) {
	f := newFixture(t)
	sj := f.signed(t)
	sj.Content = append([]byte(nil), f.content...)
	sj.Content[0] ^= 0x01
	if err := Verify(sj, f.pub, "agent-1", time.Now(), nil); !errors.Is(err, ErrContent) {
		t.Fatalf("ошибка %v, хочу ErrContent", err)
	}
}

// Изменённая цель делает подпись недействительной.
func TestVerifyTargetChanged(t *testing.T) {
	f := newFixture(t)
	sj := f.signed(t)
	sj.Envelope.AgentID = "agent-2"
	if err := Verify(sj, f.pub, "agent-1", time.Now(), nil); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("ошибка %v, хочу ErrBadSignature", err)
	}
	// И на свою цель чужое задание не проходит по цели.
	sj2, err := signing.Sign(f.env, f.priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := Verify(sj2, f.pub, "agent-9", time.Now(), nil); !errors.Is(err, ErrWrongTarget) {
		t.Fatalf("ошибка %v, хочу ErrWrongTarget", err)
	}
}

// Просроченное задание отвергается (допуск 5 минут).
func TestVerifyExpired(t *testing.T) {
	f := newFixture(t)
	f.env.IssuedAt = time.Now().Add(-2 * time.Hour)
	f.env.ExpiresAt = time.Now().Add(-ClockSkew - time.Minute)
	sj := f.signed(t)
	if err := Verify(sj, f.pub, "agent-1", time.Now(), nil); !errors.Is(err, ErrExpired) {
		t.Fatalf("ошибка %v, хочу ErrExpired", err)
	}
}

// Ещё не наступившее задание отвергается (допуск 5 минут).
func TestVerifyNotYetValid(t *testing.T) {
	f := newFixture(t)
	f.env.IssuedAt = time.Now().Add(ClockSkew + time.Minute)
	sj := f.signed(t)
	if err := Verify(sj, f.pub, "agent-1", time.Now(), nil); !errors.Is(err, ErrNotYetValid) {
		t.Fatalf("ошибка %v, хочу ErrNotYetValid", err)
	}
}

// Повтор того же job_id отвергается.
func TestVerifyReplaySameJobID(t *testing.T) {
	f := newFixture(t)
	sj := f.signed(t)
	seen, err := NewFileSeen(filepath.Join(t.TempDir(), "seen.txt"))
	if err != nil {
		t.Fatalf("FileSeen: %v", err)
	}
	defer seen.Close()
	if err := Verify(sj, f.pub, "agent-1", time.Now(), seen); err != nil {
		t.Fatalf("первый прогон: %v", err)
	}
	if err := Verify(sj, f.pub, "agent-1", time.Now(), seen); !errors.Is(err, ErrReplay) {
		t.Fatalf("ошибка %v, хочу ErrReplay", err)
	}
}

// Повтор после «перезапуска»: новый SeenStore на том же файле видит
// прошлые задания.
func TestVerifyReplayAfterRestart(t *testing.T) {
	f := newFixture(t)
	sj := f.signed(t)
	path := filepath.Join(t.TempDir(), "seen.txt")

	first, err := NewFileSeen(path)
	if err != nil {
		t.Fatalf("FileSeen: %v", err)
	}
	if err := Verify(sj, f.pub, "agent-1", time.Now(), first); err != nil {
		t.Fatalf("первый прогон: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// «Перезапуск»: агент поднялся заново, журнал с диска.
	second, err := NewFileSeen(path)
	if err != nil {
		t.Fatalf("FileSeen повторно: %v", err)
	}
	defer second.Close()
	if err := Verify(sj, f.pub, "agent-1", time.Now(), second); !errors.Is(err, ErrReplay) {
		t.Fatalf("после перезапуска ошибка %v, хочу ErrReplay", err)
	}
	// Тот же job_id с новым nonce — тоже повтор.
	f.env.Nonce[0] ^= 0xFF
	sj2 := f.signed(t)
	if err := Verify(sj2, f.pub, "agent-1", time.Now(), second); !errors.Is(err, ErrReplay) {
		t.Fatalf("новый nonce, тот же job_id: ошибка %v, хочу ErrReplay", err)
	}
}

// Файл журнала реально создаётся и содержит job_id.
func TestFileSeenPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "seen.txt")
	s, err := NewFileSeen(path)
	if err != nil {
		t.Fatalf("FileSeen: %v", err)
	}
	if err := s.Mark("job-42", "nonce-hex"); err != nil {
		t.Fatalf("Mark: %v", err)
	}
	hit, err := s.Seen("job-42", "")
	if err != nil || !hit {
		t.Fatalf("Seen в памяти: %v %v", hit, err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("файл журнала не создан: %v", err)
	}
}
