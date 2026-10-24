//go:build !windows

// На не-Windows служб нет: агент запускается в режиме run (консоль)
// для отладки и тестов. install/uninstall/status недоступны.
package agent

import "errors"

// ErrWindowsOnly — операции службы существуют только на Windows.
var ErrWindowsOnly = errors.New("agent: службы Windows доступны только на Windows")

// RunService на не-Windows не существует.
func RunService(serverURL, dir string) error { return ErrWindowsOnly }

// IsWindowsService всегда false.
func IsWindowsService() (bool, error) { return false, nil }
