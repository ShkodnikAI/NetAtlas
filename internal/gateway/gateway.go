// Package gateway — адреса шлюзов по умолчанию хоста сервера
// (NR-032 п.2). Таблица маршрутов читается через API операционной
// системы: на Windows — GetIPForwardTable2 из golang.org/x/sys/windows
// (PowerShell и Get-NetRoute не нужны), на Linux — /proc/net/route.
// Пакет ничего не отправляет в сеть: только чтение таблиц ядра.
//
// Default возвращает валидные адреса шлюзов маршрутов по умолчанию
// (0.0.0.0/0) без повторов, в порядке обнаружения. Ошибка чтения
// таблицы не паникует — вызывающий решает, как жить без шлюзов
// (карта остаётся без предполагаемых связей).
package gateway

import (
	"net/netip"
	"sort"
)

// Default — адреса шлюзов по умолчанию этой машины. Платформенная
// реализация в gateway_linux.go / gateway_windows.go.
var Default = defaultGateways

// defaultGateways — точка входа платформенного файла.
func defaultGateways() ([]netip.Addr, error) {
	return readSystem()
}

// uniq — адреса без повторов и без невалидных; результат
// отсортирован, чтобы порядок не зависел от порядка строк таблицы.
func uniq(addrs []netip.Addr) []netip.Addr {
	seen := make(map[string]bool, len(addrs))
	out := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		if !a.IsValid() || a.IsUnspecified() {
			continue
		}
		key := a.String()
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Less(out[j]) })
	return out
}
