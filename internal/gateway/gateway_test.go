package gateway

import (
	"net/netip"
	"testing"
)

// uniq отбрасывает повторы и невалидные адреса, сортирует результат.
func TestUniq(t *testing.T) {
	a := netip.AddrFrom4([4]byte{10, 0, 0, 1})
	b := netip.AddrFrom4([4]byte{192, 168, 1, 1})
	got := uniq([]netip.Addr{b, a, b, {}, netip.AddrFrom4([4]byte{0, 0, 0, 0})})
	if len(got) != 2 || got[0] != a || got[1] != b {
		t.Fatalf("uniq = %v, нужно [%v %v]", got, a, b)
	}
}
