// Ядро агента (NR-006): каталог ключей с правами, TLS-клиент к
// серверу (enroll, checkin, inventory), цикл опроса с очередью.
package agent

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// Файлы каталога агента.
const (
	keyFile  = "agent.key" // ECDSA P-256, закрытый, 0600
	certFile = "agent.pem" // сертификат от нашего CA
	caFile   = "agent-ca.pem"
)

// DefaultDir — каталог состояния агента: %ProgramData%\NetAtlas\agent
// на Windows (переопределяется переменной NETATLAS_AGENT_DIR), в
// остальных системах ~/.netatlas-agent.
func DefaultDir() string {
	if d := os.Getenv("NETATLAS_AGENT_DIR"); d != "" {
		return d
	}
	if runtime.GOOS == "windows" {
		base := os.Getenv("ProgramData")
		if base == "" {
			base = `C:\ProgramData`
		}
		return filepath.Join(base, "NetAtlas", "agent")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".netatlas-agent"
	}
	return filepath.Join(home, ".netatlas-agent")
}

// EnsureDir создаёт каталог состояния с узкими правами: на Windows —
// только SYSTEM и администраторы (icacls с фиксированными
// аргументами; проверка — в docs/AGENT.md), в остальных системах —
// 0700.
func EnsureDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("agent: каталог %s: %w", dir, err)
	}
	if runtime.GOOS == "windows" {
		return restrictACLWindows(dir, true)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("agent: права каталога: %w", err)
	}
	return nil
}

// ensureKey загружает существующий ключ агента или создаёт новый
// (ECDSA P-256, файл 0600). Существующий ключ не перезаписывается.
func ensureKey(dir string) ([]byte, error) {
	path := filepath.Join(dir, keyFile)
	if data, err := os.ReadFile(path); err == nil {
		return data, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("agent: чтение ключа: %w", err)
	}
	key, err := newAgentKey()
	if err != nil {
		return nil, err
	}
	if err := writePrivate(path, key); err != nil {
		return nil, err
	}
	return key, nil
}

// writePrivate пишет файл с правами 0600 (и ACL на Windows).
func writePrivate(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("agent: создание %s: %w", filepath.Base(path), err)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return fmt.Errorf("agent: запись %s: %w", filepath.Base(path), err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("agent: закрытие %s: %w", filepath.Base(path), err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0o600); err != nil {
			return fmt.Errorf("agent: права %s: %w", filepath.Base(path), err)
		}
		return nil
	}
	return restrictACLWindows(path, false)
}

// writePublic пишет файл с правами 0644 (сертификат, CA).
func writePublic(path string, data []byte) error {
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("agent: запись %s: %w", filepath.Base(path), err)
	}
	return nil
}
