//go:build !linux && !windows

package arp

import "context"

// ReadSystem возвращает ErrUnsupported: платформа не поддерживается.
func ReadSystem(ctx context.Context) ([]Entry, error) {
	return nil, ErrUnsupported
}
