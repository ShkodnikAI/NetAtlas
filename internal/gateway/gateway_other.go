//go:build !linux && !windows

// Платформы без реализации (сборка не должна падать): таблица
// маршрутов не читается, шлюзы неизвестны — карта работает без
// предполагаемых связей.
package gateway

import (
	"errors"
	"net/netip"
)

var errUnsupported = errors.New("gateway: платформа не поддерживается")

func readSystem() ([]netip.Addr, error) {
	return nil, errUnsupported
}
