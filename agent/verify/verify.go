// Package verify — проверка подписи задания на агенте: агент
// выполняет только подписанное.
//
// Verify отвергает задание без подписи, с чужой или неверной
// подписью, с изменённым содержимым (хэш конверта не совпал),
// просроченное, ещё не наступившее, адресованное другому агенту и
// повтор (job_id или nonce уже встречались). Любой отказ —
// типизированная ошибка; журнал увиденных заданий хранится на диске и
// переживает перезапуск агента.
package verify

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/ShkodnikAI/NetAtlas/server/signing"
)

// ClockSkew — допуск расхождения часов между сервером и агентом:
// issued_at из будущего и expires_at из прошлого в этих пределах
// принимаются.
const ClockSkew = 5 * time.Minute

// Типизированные отказы: вызывающий код различает их через errors.Is.
var (
	ErrNoSignature  = errors.New("verify: задание без подписи")
	ErrBadSignature = errors.New("verify: подпись не соответствует конверту")
	ErrContent      = errors.New("verify: содержимое не совпадает с хэшем конверта")
	ErrWrongTarget  = errors.New("verify: задание адресовано другому агенту")
	ErrNotYetValid  = errors.New("verify: задание ещё не действует")
	ErrExpired      = errors.New("verify: задание просрочено")
	ErrReplay       = errors.New("verify: повтор задания")
)

// SeenStore — журнал увиденных заданий: job_id и nonce, встреченные
// ранее. Хранится на диске агента и переживает перезапуск.
type SeenStore interface {
	// Seen сообщает, встречался ли job_id или nonce раньше.
	Seen(jobID, nonce string) (bool, error)
	// Mark записывает пару job_id, nonce как увиденную.
	Mark(jobID, nonce string) error
}

// FileSeen — SeenStore в текстовом файле: по строке «job_id nonce_hex»,
// файл только дополняется. Создаётся при первом Mark; уже увиденное
// загружается при открытии — повтор виден и после перезапуска.
type FileSeen struct {
	mu   sync.Mutex
	path string
	seen map[string]bool
	f    *os.File
}

// NewFileSeen открывает (или создаёт) файл журнала.
func NewFileSeen(path string) (*FileSeen, error) {
	s := &FileSeen{path: path, seen: map[string]bool{}}
	data, err := os.ReadFile(path)
	if err == nil {
		s.load(data)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("verify: журнал seen не читается: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("verify: журнал seen не открывается: %w", err)
	}
	s.f = f
	return s, nil
}

// load разбирает сохранённые строки; битые строки пропускаются:
// журнал не доверенный источник, но и не повод отказаться работать.
func (s *FileSeen) load(data []byte) {
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) != 2 {
			continue
		}
		s.seen[parts[0]] = true
		s.seen[parts[1]] = true
	}
}

// Seen сообщает, встречался ли job_id или nonce.
func (s *FileSeen) Seen(jobID, nonce string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.seen[jobID] || s.seen[nonce], nil
}

// Mark дописывает пару в файл (сброс на диск сразу) и в память.
func (s *FileSeen) Mark(jobID, nonce string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := fmt.Fprintf(s.f, "%s %s\n", jobID, nonce); err != nil {
		return fmt.Errorf("verify: запись в журнал seen: %w", err)
	}
	if err := s.f.Sync(); err != nil {
		return fmt.Errorf("verify: сброс журнала seen: %w", err)
	}
	s.seen[jobID] = true
	s.seen[nonce] = true
	return nil
}

// Close закрывает файл журнала.
func (s *FileSeen) Close() error {
	return s.f.Close()
}

// Verify проверяет подписанное задание: подпись, содержимое, цель,
// сроки и повтор. Порядок намеренный: подпись — раньше всего
// остального, повтор — последним (в журнал seen попадают только
// задания с верной подписью).
func Verify(sj signing.SignedJob, pub ed25519.PublicKey, selfID string, now time.Time, seen SeenStore) error {
	if len(sj.Signature) == 0 {
		return ErrNoSignature
	}
	data, err := sj.Envelope.Encode()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrBadSignature, err)
	}
	if len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, data, sj.Signature) {
		return ErrBadSignature
	}
	if len(sj.Content) > 0 {
		if !equalBytes(signing.HashContent(sj.Content), sj.Envelope.ContentSHA256) {
			return ErrContent
		}
	}
	if sj.Envelope.AgentID != selfID {
		return ErrWrongTarget
	}
	if now.Add(ClockSkew).Before(sj.Envelope.IssuedAt) {
		return ErrNotYetValid
	}
	if now.After(sj.Envelope.ExpiresAt.Add(ClockSkew)) {
		return ErrExpired
	}
	if seen != nil {
		nonce := hex.EncodeToString(sj.Envelope.Nonce)
		hit, err := seen.Seen(sj.Envelope.JobID, nonce)
		if err != nil {
			return err
		}
		if hit {
			return ErrReplay
		}
		if err := seen.Mark(sj.Envelope.JobID, nonce); err != nil {
			return err
		}
	}
	return nil
}

// equalBytes — сравнение срезов байт без раннего выхода.
func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}
