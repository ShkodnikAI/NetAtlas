package pipeline

import (
	"context"
	"net"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/ShkodnikAI/NetAtlas/internal/model"
	"github.com/ShkodnikAI/NetAtlas/scanner"
)

// DNSResolver — источник обратного DNS (NR-030): один LookupAddr на
// адрес. net.DefaultResolver удовлетворяет интерфейсу; тесты
// подставляют подставной.
type DNSResolver interface {
	LookupAddr(ctx context.Context, addr string) ([]string, error)
}

// dnsTimeout — предел времени одного обратного запроса.
const dnsTimeout = 2 * time.Second

// reverseDNS добавляет имена (источник dns, через model.NewName —
// проверки имён не обходятся) устройствам и хостам, у которых имён
// ещё нет: один LookupAddr на каждый адрес внутри границ, под
// лимитером (слот берётся на время запроса). Запросы идут только
// адресам внутри scope — fail closed, как во всём сканере. Ошибка
// резолвера и пустой ответ адрес просто пропускают: скан не роняет.
// Из ответа берётся первое имя по алфавиту (LookupAddr может вернуть
// несколько) без завершающей точки DNS. Отмена контекста останавливает
// работу и возвращается ошибкой.
func reverseDNS(ctx context.Context, devices []model.Device, hosts []model.Host, scope *scanner.Scope, limiter *scanner.Limiter, resolver DNSResolver, now time.Time) error {
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	lookup := func(ip netip.Addr) (string, bool, error) {
		if scope == nil || !scope.Contains(ip) {
			return "", false, nil // вне границ запросов нет
		}
		release, err := limiter.Acquire(ctx)
		if err != nil {
			return "", false, err
		}
		defer release()
		qctx, cancel := context.WithTimeout(ctx, dnsTimeout)
		defer cancel()
		names, err := resolver.LookupAddr(qctx, ip.String())
		if err != nil || len(names) == 0 {
			return "", false, nil // нет записи или резолвер не ответил — без имени
		}
		sort.Strings(names)
		name := strings.TrimSuffix(names[0], ".")
		return name, name != "", nil
	}

	for i := range devices {
		d := &devices[i]
		if len(d.Names) > 0 {
			continue // имя уже есть из другого источника
		}
		for _, ip := range d.IPs {
			name, ok, err := lookup(ip)
			if err != nil {
				return err // отмена контекста
			}
			if !ok {
				continue
			}
			if n, err := model.NewName(model.NameSourceDNS, name, now); err == nil {
				d.Names = append(d.Names, n)
			}
			break // достаточно одного имени на устройство
		}
	}
	for i := range hosts {
		h := &hosts[i]
		if len(h.Names) > 0 {
			continue
		}
		name, ok, err := lookup(h.IP)
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		if n, err := model.NewName(model.NameSourceDNS, name, now); err == nil {
			h.Names = append(h.Names, n)
		}
	}
	return nil
}
