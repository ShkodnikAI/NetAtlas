// Локальный журнал исполнений и политика включения (файл
// конфигурации владельца).
package exec

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// FileLogger — журнал исполнений в файл: по строке за событие, файл
// только дополняется. Записываются метаданные (идентификаторы,
// решения, коды возврата) — содержимое заданий и их вывод не пишутся:
// в выводе может быть что угодно с целевой машины.
type FileLogger struct {
	mu   sync.Mutex
	path string
}

// NewFileLogger открывает журнал (каталог создаётся).
func NewFileLogger(path string) (*FileLogger, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("exec: каталог журнала: %w", err)
	}
	return &FileLogger{path: path}, nil
}

// Logf дописывает строку с временем; ошибка записи не прерывает
// исполнение (журнал — не критичный путь, но факт потери не скрываем
// в вызывающем коде: возвращаемого значения нет намеренно).
func (l *FileLogger) Logf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "%s %s\n", time.Now().UTC().Format(time.RFC3339), fmt.Sprintf(format, args...))
}

// Политика: файл exec.json в каталоге состояния агента. Меняет только
// владелец на машине. Нет файла или он не читается — исполнение
// выключено (по умолчанию выключено всегда).

// ConfigFileName — имя файла политики в каталоге состояния.
const ConfigFileName = "exec.json"

// ExecConfig — содержимое файла политики.
type ExecConfig struct {
	// ExecEnabled — включено ли исполнение заданий. По умолчанию
	// (нет файла) — выключено.
	ExecEnabled bool `json:"exec_enabled"`
}

// LoadConfig читает политику из каталога состояния. Любая проблема
// (нет файла, битый JSON) — выключено: владелец включит явно.
func LoadConfig(dir string) ExecConfig {
	var cfg ExecConfig
	raw, err := os.ReadFile(filepath.Join(dir, ConfigFileName))
	if err != nil {
		return ExecConfig{ExecEnabled: false}
	}
	if json.Unmarshal(raw, &cfg) != nil {
		return ExecConfig{ExecEnabled: false}
	}
	return cfg
}

// WriteConfig записывает политику (для утилиты настройки и тестов;
// владелец делает это на машине руками или той же утилитой).
func WriteConfig(dir string, cfg ExecConfig) error {
	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("exec: политика: %w", err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("exec: каталог состояния: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, ConfigFileName), raw, 0o600); err != nil {
		return fmt.Errorf("exec: запись политики: %w", err)
	}
	return nil
}
