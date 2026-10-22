//go:build windows

package arp

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"time"
)

// arpCommandTimeout — предел времени на `arp -a`.
const arpCommandTimeout = 5 * time.Second

// ReadSystem читает ARP-таблицу этой машины выводом `arp -a`:
// запуск без оболочки и без параметров от пользователя, таймаут 5 секунд.
func ReadSystem(ctx context.Context) ([]Entry, error) {
	ctx, cancel := context.WithTimeout(ctx, arpCommandTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, "arp", "-a").Output()
	if err != nil {
		return nil, fmt.Errorf("arp: arp -a: %w", err)
	}
	return ParseWindows(bytes.NewReader(out))
}
