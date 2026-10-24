//go:build !windows

// Установка службы на не-Windows недоступна (см. service_other.go).
package agent

// Install недоступен вне Windows.
func Install(serverURL, dir string) error { return ErrWindowsOnly }

// Uninstall недоступен вне Windows.
func Uninstall() error { return ErrWindowsOnly }

// StatusState недоступен вне Windows.
func StatusState() (string, error) { return "", ErrWindowsOnly }
