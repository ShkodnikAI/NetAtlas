// Package store — постоянное хранилище карты сети (SQLite) поверх
// журнала аудита. Ничего из сети не читает и не пишет: вход — данные
// сканера и ручные действия, выход — копии хранимых данных.
//
// Схема создаётся встроенными миграциями (migrations/NNN_name.sql),
// версия хранится в таблице schema_version; миграции повторяемые:
// повторный запуск ничего не меняет. Секретов в базе нет.
package store

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite" // драйвер «sqlite» без cgo
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// Ошибки-сентинелы: вызывающий (API) отображает их в коды ответов.
var (
	// ErrNotFound — устройство или связь не найдены.
	ErrNotFound = errors.New("store: не найдено")
	// ErrNotManual — удаление или изменение найденного сканером
	// элемента, разрешены только ручные.
	ErrNotManual = errors.New("store: элемент не ручной")
	// ErrBackupExists — файл резервной копии уже существует.
	ErrBackupExists = errors.New("store: файл уже существует")
)

// Store — открытая база с применёнными миграциями.
type Store struct {
	db *sql.DB
}

// Open открывает базу, включает WAL и внешние ключи, применяет
// миграции. Повторный вызов на заполненной базе ничего не меняет.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("store: открытие: %w", err)
	}
	// Один писатель SQLite: соединение одно, чтобы транзакции
	// SaveScan и аудит были строго последовательны.
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`PRAGMA busy_timeout = 5000`); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: busy_timeout: %w", err)
	}
	var mode string
	if err := db.QueryRow(`PRAGMA journal_mode = WAL`).Scan(&mode); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: WAL: %w", err)
	}
	if mode != "wal" {
		db.Close()
		return nil, fmt.Errorf("store: журнал %q вместо wal", mode)
	}
	if _, err := db.Exec(`PRAGMA foreign_keys = ON`); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: внешние ключи: %w", err)
	}
	s := &Store{db: db}
	if err := s.migrate(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// Close закрывает базу.
func (s *Store) Close() error {
	return s.db.Close()
}

// DB отдаёт соединение: для чтения журнала (audit.List, audit.Verify)
// и тестов триггеров. Писать мимо store из вызывающего кода нельзя.
func (s *Store) DB() *sql.DB {
	return s.db
}

// migrate применяет встроенные миграции с версией больше текущей.
// Каждая миграция — один файл, исполняется в транзакции: либо вся,
// либо ничего.
func (s *Store) migrate(ctx context.Context) error {
	files, err := fs.Glob(migrationsFS, "migrations/*.sql")
	if err != nil {
		return fmt.Errorf("store: миграции: %w", err)
	}
	sort.Strings(files)

	type migration struct {
		version int
		name    string
		body    string
	}
	pending := make([]migration, 0, len(files))
	for _, f := range files {
		base := strings.TrimSuffix(strings.TrimPrefix(f, "migrations/"), ".sql")
		num := strings.SplitN(base, "_", 2)[0]
		v, err := strconv.Atoi(num)
		if err != nil {
			return fmt.Errorf("store: миграция %s: имя без версии: %w", f, err)
		}
		body, err := fs.ReadFile(migrationsFS, f)
		if err != nil {
			return fmt.Errorf("store: миграция %s: чтение: %w", f, err)
		}
		pending = append(pending, migration{version: v, name: base, body: string(body)})
	}

	for _, m := range pending {
		var applied int
		err := s.db.QueryRowContext(ctx,
			`SELECT COALESCE(MAX(version), 0) FROM schema_version`).Scan(&applied)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			// Таблицы ещё нет на пустой базе — считаем версию 0.
			if !strings.Contains(strings.ToLower(err.Error()), "no such table") {
				return fmt.Errorf("store: версия схемы: %w", err)
			}
			applied = 0
		}
		if m.version <= applied {
			continue // уже применена: повторный запуск ничего не меняет
		}
		if strings.HasPrefix(m.body, nonTxMarker) {
			// Внетранзакционная миграция: PRAGMA foreign_keys внутри
			// транзакции — no-op, пересоздание таблиц требует autocommit.
			// Каждый шаг файла атомарен сам по себе; порядок шагов
			// повторяемый (см. файл миграции).
			if _, err := s.db.ExecContext(ctx, m.body); err != nil {
				return fmt.Errorf("store: миграция %s: исполнение: %w", m.name, err)
			}
		} else {
			tx, err := s.db.BeginTx(ctx, nil)
			if err != nil {
				return fmt.Errorf("store: миграция %s: транзакция: %w", m.name, err)
			}
			if _, err := tx.ExecContext(ctx, m.body); err != nil {
				tx.Rollback()
				return fmt.Errorf("store: миграция %s: исполнение: %w", m.name, err)
			}
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO schema_version (version, applied_at) VALUES (?, ?)`,
				m.version, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
				tx.Rollback()
				return fmt.Errorf("store: миграция %s: отметка версии: %w", m.name, err)
			}
			if err := tx.Commit(); err != nil {
				return fmt.Errorf("store: миграция %s: фиксация: %w", m.name, err)
			}
			continue
		}
		if _, err := s.db.ExecContext(ctx,
			`INSERT INTO schema_version (version, applied_at) VALUES (?, ?)`,
			m.version, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
			return fmt.Errorf("store: миграция %s: отметка версии: %w", m.name, err)
		}
	}
	return nil
}

// nonTxMarker — первая строка внетранзакционной миграции.
const nonTxMarker = "-- nontransactional"

// SchemaVersion возвращает текущую версию схемы (0 — пустая база).
func (s *Store) SchemaVersion(ctx context.Context) (int, error) {
	var v int
	err := s.db.QueryRowContext(ctx,
		`SELECT COALESCE(MAX(version), 0) FROM schema_version`).Scan(&v)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "no such table") {
			return 0, nil
		}
		return 0, fmt.Errorf("store: версия схемы: %w", err)
	}
	return v, nil
}
