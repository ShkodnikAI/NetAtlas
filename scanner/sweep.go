package scanner

import (
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
	"sort"
	"time"

	"github.com/ShkodnikAI/NetAtlas/internal/model"
	"github.com/ShkodnikAI/NetAtlas/scanner/ping"
)

// Hosts перечисляет адреса хостов всех префиксов scope по возрастанию,
// без повторов (перекрывающиеся CIDR дают адрес один раз). Сетевой и
// широковещательный адрес исключаются; для префикса из одного адреса
// (/32) возвращается сам адрес, для /31 — оба адреса (RFC 3021).
// nil-Scope даёт пустой срез, не nil.
func Hosts(scope *Scope) []netip.Addr {
	out := make([]netip.Addr, 0)
	if scope == nil {
		return out
	}
	seen := make(map[uint32]bool)
	for _, p := range scope.prefixes {
		base := p.Masked().Addr().As4()
		start := binary.BigEndian.Uint32(base[:])
		size := uint32(1) << uint(32-p.Bits())
		lo, hi := start, start+size-1 // границы диапазона
		switch size {
		case 1: // /32 — единственный адрес
		case 2: // /31 — оба адреса
		default:
			lo++ // без сетевого
			hi-- // без широковещательного
		}
		for a := lo; a >= start && a <= hi; a++ {
			if seen[a] {
				continue
			}
			seen[a] = true
			var b [4]byte
			binary.BigEndian.PutUint32(b[:], a)
			out = append(out, netip.AddrFrom4(b))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Less(out[j]) })
	return out
}

// Sweep опрашивает адреса ICMP-эхом через Prober. Каждый адрес обязан
// проходить scope.Contains — адрес вне границ не опрашивается (fail
// closed, вторая линия защиты после Hosts). Частота и параллельность
// ограничены Limiter'ом. Живые адреса возвращаются моделью Host с
// одним наблюдением источника «ping», результат — по возрастанию IP.
// Отмена контекста возвращает собранное и ctx.Err().
func Sweep(ctx context.Context, scope *Scope, limiter *Limiter, p ping.Prober, hosts []netip.Addr, now time.Time) ([]model.Host, error) {
	if scope == nil {
		return nil, fmt.Errorf("scanner: sweep: границы не заданы")
	}
	if limiter == nil {
		return nil, fmt.Errorf("scanner: sweep: ограничитель не задан")
	}
	if p == nil {
		return nil, fmt.Errorf("scanner: sweep: пробер не задан")
	}

	out := make([]model.Host, 0)
	for _, ip := range hosts {
		if ctx.Err() != nil {
			return out, ctx.Err()
		}
		if !scope.Contains(ip) {
			continue
		}
		release, err := limiter.Acquire(ctx)
		if err != nil {
			return out, err
		}
		rtt, alive, err := p.Ping(ctx, ip)
		release()
		if err != nil {
			return out, err
		}
		if !alive {
			continue
		}
		h, err := model.NewHost(ip)
		if err != nil {
			continue // адреса из scope всегда валидные IPv4; страховка
		}
		h.RTT = rtt
		h.Observations = append(h.Observations, model.Observation{Source: "ping", Seen: now})
		out = append(out, h)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP.Less(out[j].IP) })
	return out, nil
}
