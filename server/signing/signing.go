// Package signing — подпись заданий для агентов (ed25519).
//
// Подпись покрывает канонически закодированный конверт задания:
// job_id, agent_id (цель), kind, SHA-256 содержимого, issued_at,
// expires_at, nonce. Кодирование длинно-префиксное и детерминированное
// (не JSON со свободным порядком полей): один и тот же конверт даёт
// одни и те же байты на любой машине.
//
// Модуль ключей не хранит: ключ подписи передаёт вызывающая сторона
// (сервер читает его из каталога ключей NETATLAS_KEYDIR). Закрытые
// ключи через этот пакет не передаются и в ответы не попадают.
package signing

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"time"
)

// envelopeDomain — разделитель домена подписи: байты чужого протокола
// не могут быть приняты за конверт задания.
var envelopeDomain = []byte("NETATLAS-JOB-1\x00")

// NonceSize — размер nonce и ContentSHA256 в байтах.
const NonceSize = 32

// Envelope — конверт задания: то, что покрывает подпись.
// ContentSHA256 — SHA-256 содержимого; Nonce — 32 случайных байта для
// защиты от повтора.
type Envelope struct {
	JobID         string    `json:"job_id"`
	AgentID       string    `json:"agent_id"`
	Kind          string    `json:"kind"`
	ContentSHA256 []byte    `json:"content_sha256"`
	IssuedAt      time.Time `json:"issued_at"`
	ExpiresAt     time.Time `json:"expires_at"`
	Nonce         []byte    `json:"nonce"`
}

// SignedJob — конверт с подписью и (при передаче) содержимым.
// Подпись — ed25519 над каноническими байтами конверта.
type SignedJob struct {
	Envelope  Envelope `json:"envelope"`
	Signature []byte   `json:"signature"`
	// Content — само задание; при передаче проверяется против
	// ContentSHA256 (agent/verify).
	Content []byte `json:"content,omitempty"`
}

// HashContent — SHA-256 содержимого для поля ContentSHA256.
func HashContent(content []byte) []byte {
	h := sha256.Sum256(content)
	return h[:]
}

// Encode — канонические байты конверта: домен, затем каждое поле
// длинно-префиксно (uvarint длина + байты). Время — UTC RFC 3339 с
// наносекундами, чтобы кодирование не зависело от зоны. Публично:
// agent/verify пересобирает байты для проверки подписи.
func (e Envelope) Encode() ([]byte, error) {
	if len(e.ContentSHA256) != NonceSize {
		return nil, fmt.Errorf("signing: content_sha256: нужно %d байт, получено %d", NonceSize, len(e.ContentSHA256))
	}
	if len(e.Nonce) != NonceSize {
		return nil, fmt.Errorf("signing: nonce: нужно %d байт, получено %d", NonceSize, len(e.Nonce))
	}
	if e.IssuedAt.IsZero() || e.ExpiresAt.IsZero() {
		return nil, fmt.Errorf("signing: конверт без времени")
	}
	buf := make([]byte, 0, 256)
	buf = append(buf, envelopeDomain...)
	put := func(b []byte) {
		buf = binary.AppendUvarint(buf, uint64(len(b)))
		buf = append(buf, b...)
	}
	put([]byte(e.JobID))
	put([]byte(e.AgentID))
	put([]byte(e.Kind))
	put(e.ContentSHA256)
	put([]byte(e.IssuedAt.UTC().Format(time.RFC3339Nano)))
	put([]byte(e.ExpiresAt.UTC().Format(time.RFC3339Nano)))
	put(e.Nonce)
	return buf, nil
}

// Sign подписывает конверт ключом вызывающей стороны. Ключ нигде не
// сохраняется; конверт без подписи возвращается с ошибкой — задание
// без подписи не существует.
func Sign(env Envelope, key ed25519.PrivateKey) (SignedJob, error) {
	if len(key) != ed25519.PrivateKeySize {
		return SignedJob{}, fmt.Errorf("signing: ключ подписи неверного размера")
	}
	if env.ExpiresAt.Before(env.IssuedAt) {
		return SignedJob{}, fmt.Errorf("signing: expires_at раньше issued_at")
	}
	data, err := env.Encode()
	if err != nil {
		return SignedJob{}, err
	}
	sig := ed25519.Sign(key, data)
	return SignedJob{Envelope: env, Signature: sig}, nil
}
