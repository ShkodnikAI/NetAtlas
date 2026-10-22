//go:build linux

package arp

import (
	"context"
	"testing"
)

// ReadSystem на реальной машине: /proc/net/arp должен читаться без ошибки.
func TestReadSystemLinux(t *testing.T) {
	entries, err := ReadSystem(context.Background())
	if err != nil {
		t.Fatalf("ReadSystem: неожиданная ошибка: %v", err)
	}
	if entries == nil {
		t.Error("ReadSystem вернул nil-срез вместо пустого")
	}
}
