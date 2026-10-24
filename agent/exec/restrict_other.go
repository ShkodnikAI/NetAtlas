//go:build !windows

// Вне Windows icacls не существует: раннер здесь и не используется.
package exec

import "errors"

func restrict(string) error {
	return errors.New("exec: icacls недоступен вне Windows")
}
