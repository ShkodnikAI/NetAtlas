//go:build windows

package arp

import (
	"context"
	"testing"
)

// ReadSystem на реальной машине: `arp -a` должен отработать без ошибки.
func TestReadSystemWindows(t *testing.T) {
	entries, err := ReadSystem(context.Background())
	if err != nil {
		t.Fatalf("ReadSystem: неожиданная ошибка: %v", err)
	}
	if entries == nil {
		t.Error("ReadSystem вернул nil-срез вместо пустого")
	}
}
