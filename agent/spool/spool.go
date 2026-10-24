package spool

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// DefaultMaxBytes — суммарный лимит очереди (наряд: не больше 20 МБ).
const DefaultMaxBytes = 20 << 20

// ErrEmpty — очередь пуста.
var ErrEmpty = errors.New("spool: очередь пуста")

// Spool — файловая очередь в каталоге dir.
type Spool struct {
	dir string
	max int64
	mu  sync.Mutex
}

// Open открывает (при необходимости создаёт) каталог очереди.
// max <= 0 заменяется на DefaultMaxBytes.
func Open(dir string, max int64) (*Spool, error) {
	if max <= 0 {
		max = DefaultMaxBytes
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("spool: каталог %s: %w", dir, err)
	}
	return &Spool{dir: dir, max: max}, nil
}

// MaxBytes — суммарный лимит очереди.
func (s *Spool) MaxBytes() int64 { return s.max }

// Push добавляет отчёт в конец очереди и вытесняет самое старое,
// если суммарный объём превысил лимит.
func (s *Spool) Push(data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	name, err := newName()
	if err != nil {
		return err
	}
	path := filepath.Join(s.dir, name)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("spool: запись %s: %w", name, err)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(path)
		return fmt.Errorf("spool: запись %s: %w", name, err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(path)
		return fmt.Errorf("spool: fsync %s: %w", name, err)
	}
	if err := f.Close(); err != nil {
		os.Remove(path)
		return fmt.Errorf("spool: закрытие %s: %w", name, err)
	}
	s.evictLocked()
	return nil
}

// Pop отдаёт самую старую запись. Файл остаётся на месте до Ack:
// сбой после Pop приведёт к повторной отправке (at-least-once).
func (s *Spool) Pop() (id string, data []byte, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	names, err := s.listLocked()
	if err != nil {
		return "", nil, err
	}
	if len(names) == 0 {
		return "", nil, ErrEmpty
	}
	id = names[0]
	data, err = os.ReadFile(filepath.Join(s.dir, id))
	if err != nil {
		return "", nil, fmt.Errorf("spool: чтение %s: %w", id, err)
	}
	return id, data, nil
}

// Ack подтверждает отправку: запись удаляется.
func (s *Spool) Ack(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !validName(id) {
		return fmt.Errorf("spool: недопустимый идентификатор %q", id)
	}
	if err := os.Remove(filepath.Join(s.dir, id)); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("spool: удаление %s: %w", id, err)
	}
	return nil
}

// Len — число записей в очереди.
func (s *Spool) Len() (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	names, err := s.listLocked()
	if err != nil {
		return 0, err
	}
	return len(names), nil
}

// TotalBytes — суммарный объём записей.
func (s *Spool) TotalBytes() (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.totalLocked()
}

// evictLocked вытесняет самые старые записи, пока объём превышает лимит.
func (s *Spool) evictLocked() {
	for {
		total, err := s.totalLocked()
		if err != nil || total <= s.max {
			return
		}
		names, err := s.listLocked()
		if err != nil || len(names) == 0 {
			return
		}
		// Самое старое вытесняется, даже если его не удалось ещё
		// отправить: свежие данные важнее старых.
		if err := os.Remove(filepath.Join(s.dir, names[0])); err != nil && !os.IsNotExist(err) {
			return
		}
	}
}

// listLocked — имена файлов очереди по возрастанию (старые сверху).
func (s *Spool) listLocked() ([]string, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, fmt.Errorf("spool: чтение каталога: %w", err)
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !validName(e.Name()) {
			continue
		}
		out = append(out, e.Name())
	}
	sort.Strings(out)
	return out, nil
}

func (s *Spool) totalLocked() (int64, error) {
	names, err := s.listLocked()
	if err != nil {
		return 0, err
	}
	var total int64
	for _, n := range names {
		fi, err := os.Stat(filepath.Join(s.dir, n))
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return 0, fmt.Errorf("spool: размер %s: %w", n, err)
		}
		total += fi.Size()
	}
	return total, nil
}

// newName — уникальное монотонное имя: время в наносекундах +
// случайный хвост (два агента в одну наносекунду не попадут).
func newName() (string, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("spool: случайный хвост имени: %w", err)
	}
	return fmt.Sprintf("%019d-%s.json", timeNowUnixNano(), hex.EncodeToString(b[:])), nil
}

// validName — имена только собственного формата: 19 цифр, дефис,
// 8 hex-символов, .json. Никаких путей и чужих файлов.
func validName(name string) bool {
	if !strings.HasSuffix(name, ".json") || len(name) != 19+1+8+5 {
		return false
	}
	for i := 0; i < 19; i++ {
		if name[i] < '0' || name[i] > '9' {
			return false
		}
	}
	if name[19] != '-' {
		return false
	}
	for i := 20; i < 28; i++ {
		c := name[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// timeNowUnixNano — точка подмены в тестах (монотонность имён).
func timeNowUnixNano() int64 { return time.Now().UnixNano() }
