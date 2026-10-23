package store

import (
	"context"
	"errors"
	"fmt"
	"os"
)

// Backup создаёт резервную копию базы через VACUUM INTO: копия
// всегда консистентна, независимо от параллельных транзакций.
// Существующий файл не перезаписывается.
func (s *Store) Backup(ctx context.Context, path string) error {
	if path == "" {
		return fmt.Errorf("store: путь копии пуст")
	}
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("store: %w: %s", ErrBackupExists, path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("store: путь копии %s: %w", path, err)
	}
	if _, err := s.db.ExecContext(ctx, `VACUUM INTO ?`, path); err != nil {
		return fmt.Errorf("store: копия %s: %w", path, err)
	}
	return nil
}
