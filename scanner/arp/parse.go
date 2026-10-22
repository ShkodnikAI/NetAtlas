// Package arp — чтение и разбор ARP-таблицы самой машины.
package arp

import (
	"fmt"
	"io"
	"net/netip"
	"strings"

	"github.com/ShkodnikAI/NetAtlas/internal/model"
)

// Entry — одна запись ARP-таблицы. MAC нормализован через model.NormalizeMAC.
type Entry struct {
	IP  netip.Addr
	MAC string
}

// ParseLinux разбирает формат /proc/net/arp. Пропускает: заголовок,
// неполные записи (флаги 0x0), групповые IP (224.0.0.0/4) и MAC,
// не проходящие NormalizeMAC (включая широковещательные и нулевые).
// Дубликаты (тот же IP и MAC) схлопываются.
func ParseLinux(r io.Reader) ([]Entry, error) {
	return parseTable(r, parseLinuxLine)
}

// ParseWindows разбирает вывод `arp -a` независимо от языка ОС:
// строки разбираются по шаблону «IPv4, пробелы, MAC», любые слова
// игнорируются; строки-заголовки интерфейса (содержат ---) пропускаются.
func ParseWindows(r io.Reader) ([]Entry, error) {
	return parseTable(r, parseWindowsLine)
}

func parseTable(r io.Reader, line func(fields []string) (Entry, bool)) ([]Entry, error) {
	all, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("arp: чтение входа: %w", err)
	}
	seen := make(map[string]bool)
	var out []Entry
	for _, ln := range strings.Split(string(all), "\n") {
		fields := strings.Fields(strings.TrimSuffix(ln, "\r"))
		if len(fields) == 0 {
			continue
		}
		e, ok := line(fields)
		if !ok {
			continue
		}
		key := e.IP.String() + "|" + e.MAC
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, e)
	}
	return out, nil
}

// parseLinuxLine разбирает поля одной строки /proc/net/arp:
// IP address, HW type, Flags, HW address, Mask, Device.
func parseLinuxLine(fields []string) (Entry, bool) {
	if len(fields) < 4 || fields[0] == "IP" {
		return Entry{}, false // заголовок или мусор
	}
	if fields[2] == "0x0" {
		return Entry{}, false // неполная запись
	}
	return buildEntry(fields[0], fields[3])
}

// parseWindowsLine разбирает поля одной строки вывода arp -a
// независимо от языка: «IPv4, пробелы, MAC», слова игнорируются.
func parseWindowsLine(fields []string) (Entry, bool) {
	for _, f := range fields {
		if f == "---" {
			return Entry{}, false // заголовок интерфейса
		}
	}
	if len(fields) < 2 {
		return Entry{}, false
	}
	return buildEntry(fields[0], fields[1])
}

// buildEntry проверяет пару IP и MAC и возвращает запись.
// Пропускает групповые IP (224.0.0.0/4) и MAC, не проходящие
// NormalizeMAC: нулевые, широковещательные и групповые в том числе.
func buildEntry(ipStr, macStr string) (Entry, bool) {
	ip, err := netip.ParseAddr(ipStr)
	if err != nil || !ip.Is4() || ip.IsMulticast() {
		return Entry{}, false
	}
	mac, err := model.NormalizeMAC(macStr)
	if err != nil {
		return Entry{}, false
	}
	return Entry{IP: ip, MAC: mac}, true
}
