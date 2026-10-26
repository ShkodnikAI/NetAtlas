//go:build linux

package gateway

import (
	"net/netip"
	"testing"
)

// Разбор /proc/net/route: маршрут по умолчанию с little-endian
// адресом шлюза и обычные маршруты, которые не являются шлюзами.
// Адрес 192.168.1.1 хранится в памяти байтами C0 A8 01 01 (сетевой
// порядок), little-endian u32 от них печатается как 0101A8C0.
func TestParseProcRoute(t *testing.T) {
	data := "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n" +
		"eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n" + // шлюз 192.168.1.1
		"eth0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n" + // подсеть без шлюза
		"wlan0\t00000000\t0202000A\t0003\t0\t0\t600\t00000000\t0\t0\t0\n" + // шлюз 10.0.2.2
		"eth0\t0101A8C1\t00000000\t0005\t0\t0\t0\tFFFFFFFF\t0\t0\t0\n" + // host-маршрут
		"eth0\t00000000\t0102030405\t0003\t0\t0\t100\t00000000\t0\t0\t0\n" // мусорная длина
	got := parseProcRoute(data)
	want := []netip.Addr{
		netip.AddrFrom4([4]byte{10, 0, 2, 2}),
		netip.AddrFrom4([4]byte{192, 168, 1, 1}),
	}
	if len(got) != len(want) {
		t.Fatalf("parseProcRoute = %v, нужно %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("parseProcRoute[%d] = %v, нужно %v", i, got[i], want[i])
		}
	}
}

// Пустая таблица и мусор — не ошибка: шлюзов просто нет.
func TestParseProcRouteEmpty(t *testing.T) {
	if got := parseProcRoute(""); len(got) != 0 {
		t.Fatalf("parseProcRoute(\"\") = %v, нужен пустой срез", got)
	}
	if got := parseProcRoute("Iface\tDestination\tGateway\n"); len(got) != 0 {
		t.Fatalf("заголовок без строк: %v", got)
	}
}
