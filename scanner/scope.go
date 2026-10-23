package scanner

import (
	"fmt"
	"net/netip"
)

// Scope — список разрешённых подсетей. Сканер не трогает адреса
// вне списка (антипаттерн «сканирование за пределами заданных подсетей»).
type Scope struct {
	prefixes []netip.Prefix
}

// Запрещённые диапазоны: loopback, групповые, «эта сеть» и link-local.
var forbiddenRanges = []struct {
	name   string
	prefix netip.Prefix
}{
	{"loopback", netip.MustParsePrefix("127.0.0.0/8")},
	{"multicast", netip.MustParsePrefix("224.0.0.0/4")},
	{"this-network", netip.MustParsePrefix("0.0.0.0/8")},
	{"link-local", netip.MustParsePrefix("169.254.0.0/16")},
}

// NewScope создаёт границы из списка CIDR. allowLarge разрешает подсети
// шире /22 (более 1024 адресов). Ошибки: пустой список; неверный CIDR;
// IPv6; loopback 127.0.0.0/8; групповые 224.0.0.0/4; 0.0.0.0/8;
// link-local 169.254.0.0/16; префикс шире /22 без allowLarge.
func NewScope(cidrs []string, allowLarge bool) (*Scope, error) {
	if len(cidrs) == 0 {
		return nil, fmt.Errorf("scanner: список подсетей пуст")
	}
	s := &Scope{prefixes: make([]netip.Prefix, 0, len(cidrs))}
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return nil, fmt.Errorf("scanner: неверный CIDR %q: %w", c, err)
		}
		if !p.Addr().Is4() {
			return nil, fmt.Errorf("scanner: CIDR %q: IPv6 не поддерживается", c)
		}
		for _, f := range forbiddenRanges {
			if overlapsPrefix(p, f.prefix) {
				return nil, fmt.Errorf("scanner: CIDR %q попадает в запрещённый диапазон %s", c, f.name)
			}
		}
		if p.Bits() < 22 && !allowLarge {
			return nil, fmt.Errorf("scanner: CIDR %q шире /22 (более 1024 адресов), нужен allowLarge", c)
		}
		s.prefixes = append(s.prefixes, p.Masked())
	}
	return s, nil
}

// overlapsPrefix сообщает, пересекаются ли два префикса.
func overlapsPrefix(p, f netip.Prefix) bool {
	return f.Contains(p.Addr()) || p.Contains(f.Addr())
}

// ContainsPrefix истинно только для подсети, целиком лежащей внутри
// одной из разрешённых: интерфейс может выбрать подмножество границ,
// но не расширить их (NR-005).
func (s *Scope) ContainsPrefix(p netip.Prefix) bool {
	p = p.Masked()
	if !p.IsValid() {
		return false
	}
	for _, allowed := range s.prefixes {
		if p.Bits() >= allowed.Bits() && allowed.Contains(p.Addr()) {
			return true
		}
	}
	return false
}

// Prefixes возвращает копию списка разрешённых подсетей.
func (s *Scope) Prefixes() []netip.Prefix {
	out := make([]netip.Prefix, len(s.prefixes))
	copy(out, s.prefixes)
	return out
}

// Contains истинно только для адреса внутри хотя бы одной разрешённой подсети.
func (s *Scope) Contains(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	for _, p := range s.prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}
