//go:build windows

// Windows-реализация чтения шлюзов по умолчанию (NR-032 п.2):
// GetIpForwardTable2 из golang.org/x/sys/windows — прямой вызов API
// ОС; PowerShell и Get-NetRoute не нужны. Маршруты по умолчанию —
// строки с DestinationPrefix.PrefixLength == 0. Память таблицы
// освобождается FreeMibTable, как требует протокол iphlpapi.
package gateway

import (
	"fmt"
	"net/netip"
	"unsafe"

	"golang.org/x/sys/windows"
)

// readSystem — адреса шлюзов маршрутов по умолчанию (IPv4 и IPv6).
func readSystem() ([]netip.Addr, error) {
	out := make([]netip.Addr, 0, 2)
	for _, family := range []uint16{windows.AF_INET, windows.AF_INET6} {
		rows, err := forwardRows(family)
		if err != nil {
			return nil, err
		}
		for _, r := range rows {
			if r.DestinationPrefix.PrefixLength != 0 {
				continue // маршрут не по умолчанию
			}
			if a := sockaddrToAddr(r.NextHop); a.IsValid() {
				out = append(out, a)
			}
		}
	}
	return uniq(out), nil
}

// forwardRows — строки таблицы маршрутов одного семейства; память
// освобождается до возврата, срез ссылается на собственную копию
// значений (MibIpForwardRow2 — значения без указателей).
func forwardRows(family uint16) ([]windows.MibIpForwardRow2, error) {
	var table *windows.MibIpForwardTable2
	if err := windows.GetIpForwardTable2(family, &table); err != nil {
		return nil, fmt.Errorf("gateway: GetIpForwardTable2(family=%d): %w", family, err)
	}
	defer windows.FreeMibTable(unsafe.Pointer(table))
	rows := table.Rows()
	out := make([]windows.MibIpForwardRow2, len(rows))
	copy(out, rows)
	return out, nil
}

// sockaddrToAddr — SOCKADDR_INET (union RawSockaddrInet) в netip.Addr:
// семейство AF_INET — первые 4 байта Data, AF_INET6 — все 24 байта
// Data как in6_addr. Неизвестное семейство даёт невалидный адрес
// (uniq его отбросит).
func sockaddrToAddr(sa windows.RawSockaddrInet) netip.Addr {
	switch sa.Family {
	case windows.AF_INET:
		var b [4]byte
		raw := (*[4]byte)(unsafe.Pointer(&sa.Data[0]))
		copy(b[:], raw[:])
		return netip.AddrFrom4(b)
	case windows.AF_INET6:
		var b [16]byte
		raw := (*[16]byte)(unsafe.Pointer(&sa.Data[0]))
		copy(b[:], raw[:])
		return netip.AddrFrom16(b)
	default:
		return netip.Addr{}
	}
}
