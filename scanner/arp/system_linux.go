//go:build linux

package arp

import (
	"context"
	"fmt"
	"os"
)

// ReadSystem читает ARP-таблицу этой машины из /proc/net/arp.
func ReadSystem(ctx context.Context) ([]Entry, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f, err := os.Open("/proc/net/arp")
	if err != nil {
		return nil, fmt.Errorf("arp: /proc/net/arp: %w", err)
	}
	defer f.Close()
	return ParseLinux(f)
}
