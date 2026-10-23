package scanner

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"time"

	"github.com/ShkodnikAI/NetAtlas/internal/model"
	"github.com/ShkodnikAI/NetAtlas/scanner/arp"
	"github.com/ShkodnikAI/NetAtlas/scanner/names"
	"github.com/ShkodnikAI/NetAtlas/scanner/ping"
)

// Options — что включает конвейер сканирования. Ping требует Prober,
// Names требует NameClient; несоответствие — ошибка Run.
type Options struct {
	Ping       bool
	Names      bool
	Now        time.Time
	Prober     ping.Prober   // обязателен при Ping
	NameClient *names.Client // обязателен при Names
	// SkipNamesForMACs — MAC устройств, которые не опрашиваются по
	// именам (NetBIOS, mDNS): гости и «известные без агента»
	// (NR-005). Хосты без MAC не имеют классов и не пропускаются.
	SkipNamesForMACs map[string]bool
	// SkipSSDPForIPs — адреса (строки netip), чьи ответы SSDP не
	// сохраняются (NR-023): гости и «известные без агента».
	// Групповой M-SEARCH отвечает всем, поэтому имя из ответа такого
	// адреса отбрасывается; присутствие (ARP/ping) не трогается.
	SkipSSDPForIPs map[string]bool
}

// Result — итог сканирования: устройства (с MAC) и хосты без MAC.
// Оба среза пустые, но не nil, чтобы в JSON были [].
type Result struct {
	Devices []model.Device `json:"devices"`
	Hosts   []model.Host   `json:"hosts"`
}

// Run исполняет конвейер: ARP-таблица → устройства; при Ping — опрос
// адресов границ (живой IP устройства получает наблюдение «ping»,
// живой IP без устройства становится хостом); при Names — имена по
// NetBIOS и mDNS для каждого IP, затем один SSDP-запрос (ответы вне
// границ отбрасываются). Все unicast-запросы — только адресам внутри
// scope, и весь активный трафик (ping, имена, SSDP) идёт под
// лимитером: каждый запрос берёт слот перед отправкой и отпускает
// после ответа или таймаута. nil-лимитер при Names — ошибка, как
// и в Sweep. Отмена контекста возвращает собранное и ошибку.
func Run(ctx context.Context, entries []arp.Entry, scope *Scope, limiter *Limiter, opt Options) (Result, error) {
	now := opt.Now
	if now.IsZero() {
		now = time.Now()
	}
	devices := FromARP(entries, scope, now)
	hosts := make([]model.Host, 0)

	if opt.Ping {
		if opt.Prober == nil {
			return Result{}, fmt.Errorf("scanner: ping включён, но пробер не задан")
		}
		alive, err := Sweep(ctx, scope, limiter, opt.Prober, Hosts(scope), now)
		if err != nil {
			return Result{}, err
		}
		for _, h := range alive {
			matched := false
			for i := range devices {
				if containsAddr(devices[i].IPs, h.IP) {
					matched = true
					if !hasSource(devices[i].Observations, "ping") {
						devices[i].Observations = append(devices[i].Observations,
							model.Observation{Source: "ping", Seen: now})
					}
					break
				}
			}
			if !matched {
				hosts = append(hosts, h)
			}
		}
	}

	if opt.Names {
		if opt.NameClient == nil {
			return Result{}, fmt.Errorf("scanner: names включён, но клиент имён не задан")
		}
		if limiter == nil {
			return Result{}, fmt.Errorf("scanner: names включён, но ограничитель не задан")
		}
		for i := range devices {
			d := &devices[i]
			if opt.SkipNamesForMACs[d.ID] {
				continue // глубокого опроса гостей и «известных» нет
			}
			for _, ip := range d.IPs {
				n, ok, err := resolveName(ctx, opt.NameClient, ip, scope, limiter)
				if err != nil {
					return Result{}, err
				}
				if !ok {
					continue
				}
				name, err := model.NewName(n.Source, n.Name, now)
				if err != nil {
					continue // парсер не выдаёт недопустимых имён; страховка
				}
				d.Names = append(d.Names, name)
				break // достаточно одного имени из NetBIOS/mDNS
			}
		}
		for i := range hosts {
			h := &hosts[i]
			n, ok, err := resolveName(ctx, opt.NameClient, h.IP, scope, limiter)
			if err != nil {
				return Result{}, err
			}
			if !ok {
				continue
			}
			name, err := model.NewName(n.Source, n.Name, now)
			if err != nil {
				continue
			}
			h.Names = append(h.Names, name)
		}
		if err := attachSSDP(ctx, opt.NameClient, limiter, scope, now, devices, hosts, opt.SkipSSDPForIPs); err != nil {
			return Result{}, err
		}
	}

	sort.Slice(hosts, func(i, j int) bool { return hosts[i].IP.Less(hosts[j].IP) })
	return Result{Devices: devices, Hosts: hosts}, nil
}

// nameQuery выполняет один запрос имени под слотом лимитера: слот
// берётся перед отправкой и отпускается после ответа или таймаута,
// так что параллельность и частота запросов имён ограничены так же,
// как ping-sweep.
func nameQuery(ctx context.Context, limiter *Limiter, q func(context.Context) (string, bool, error)) (string, bool, error) {
	release, err := limiter.Acquire(ctx)
	if err != nil {
		return "", false, err
	}
	defer release()
	return q(ctx)
}

// resolveName спрашивает имя по NetBIOS, при пустом результате — mDNS.
// Каждый unicast-запрос берёт слот лимитера. unicast разрешён только
// адресам внутри границ; nil-Scope никого не пропускает (fail closed,
// как во всём сканере).
func resolveName(ctx context.Context, c *names.Client, ip netip.Addr, scope *Scope, limiter *Limiter) (model.Name, bool, error) {
	if scope == nil || !scope.Contains(ip) {
		return model.Name{}, false, nil
	}
	if n, ok, err := nameQuery(ctx, limiter, func(ctx context.Context) (string, bool, error) {
		return c.NetBIOSName(ctx, ip)
	}); err != nil {
		return model.Name{}, false, err
	} else if ok {
		return model.Name{Source: model.NameSourceNetBIOS, Name: n}, true, nil
	}
	if n, ok, err := nameQuery(ctx, limiter, func(ctx context.Context) (string, bool, error) {
		return c.MDNSName(ctx, ip)
	}); err != nil {
		return model.Name{}, false, err
	} else if ok {
		return model.Name{Source: model.NameSourceMDNS, Name: n}, true, nil
	}
	return model.Name{}, false, nil
}

// attachSSDP выполняет один M-SEARCH и прикрепляет имена (источник
// ssdp) устройствам и хостам по адресу отправителя. Единственный
// M-SEARCH берёт один слот лимитера на время отправки и окна сбора
// ответов. Ответы от адресов вне границ и адресов из skipSSDP
// (гости и «известные без агента», NR-023) отбрасываются —
// присутствие и ping не трогаются.
func attachSSDP(ctx context.Context, c *names.Client, limiter *Limiter, scope *Scope, now time.Time, devices []model.Device, hosts []model.Host, skipSSDP map[string]bool) error {
	release, err := limiter.Acquire(ctx)
	if err != nil {
		return err
	}
	infos, ssdpErr := c.SSDP(ctx)
	release()
	if ssdpErr != nil {
		return ssdpErr
	}
	// Детерминированный порядок обхода ответов.
	addrs := make([]netip.Addr, 0, len(infos))
	for ip := range infos {
		addrs = append(addrs, ip)
	}
	sort.Slice(addrs, func(i, j int) bool { return addrs[i].Less(addrs[j]) })

	for _, ip := range addrs {
		if scope == nil || !scope.Contains(ip) {
			continue // ответ вне границ не принимается
		}
		if skipSSDP != nil && skipSSDP[ip.String()] {
			continue // гость или «известный без агента»: имя не сохраняется
		}
		info := infos[ip]
		name := info.Server
		if name == "" {
			name = info.Location
		}
		if name == "" {
			continue
		}
		n, err := model.NewName(model.NameSourceSSDP, name, now)
		if err != nil {
			continue // заголовки ограничены парсером SSDP; страховка
		}
		matched := false
		for i := range devices {
			if containsAddr(devices[i].IPs, ip) {
				devices[i].Names = append(devices[i].Names, n)
				matched = true
				break
			}
		}
		if !matched {
			for i := range hosts {
				if hosts[i].IP == ip {
					hosts[i].Names = append(hosts[i].Names, n)
					break
				}
			}
		}
	}
	return nil
}

func hasSource(observations []model.Observation, source string) bool {
	for _, o := range observations {
		if o.Source == source {
			return true
		}
	}
	return false
}
