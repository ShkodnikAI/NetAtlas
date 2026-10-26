//go:build linux

// Linux-реализация чтения шлюзов по умолчанию (NR-032 п.2): таблица
// /proc/net/route — штатный интерфейс ядра; строки маршрутов
// 0.0.0.0/0 содержат адрес шлюза в поле Gateway (hex, little-endian).
package gateway

import (
	"fmt"
	"net/netip"
	"os"
	"strings"
)

// routeFile — путь к таблице маршрутов; переменная для тестов.
var routeFile = "/proc/net/route"

// readSystem — адреса шлюзов маршрутов по умолчанию.
func readSystem() ([]netip.Addr, error) {
	data, err := os.ReadFile(routeFile)
	if err != nil {
		return nil, fmt.Errorf("gateway: %s: %w", routeFile, err)
	}
	return parseProcRoute(string(data)), nil
}

// parseProcRoute разбирает содержимое /proc/net/route: заголовок
// пропускается, маршруты с Destination 00000000 — по умолчанию,
// их Gateway — адрес шлюза (hex little-endian, разделители табами).
func parseProcRoute(data string) []netip.Addr {
	lines := strings.Split(data, "\n")
	out := make([]netip.Addr, 0, 2)
	for i, line := range lines {
		if i == 0 || line == "" {
			continue // заголовок и пустой хвост
		}
		fields := strings.Fields(line)
		// Iface Destination Gateway Flags ...
		if len(fields) < 3 {
			continue
		}
		if fields[1] != "00000000" {
			continue // маршрут не по умолчанию
		}
		raw := fields[2]
		if len(raw) != 8 {
			continue
		}
		var b [4]byte
		for j := 0; j < 4; j++ {
			hi := hexVal(raw[2*j])
			lo := hexVal(raw[2*j+1])
			if hi < 0 || lo < 0 {
				b[3-j] = 0
				continue
			}
			// little-endian: поле Gateway хранит адрес задом наперёд
			b[3-j] = byte(hi)<<4 | byte(lo)
		}
		out = append(out, netip.AddrFrom4(b))
	}
	return uniq(out)
}

func hexVal(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	}
	return -1
}
