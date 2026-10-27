package store

// Пересчёт автоматических типов при старте сервера и резерв
// шлюзов по умолчанию (NR-034, уточнение аудитора): данные скана,
// записанные версией до NR-032, оставляют карту «глупой» — kind_auto
// пуст, шлюзов нет, все узлы device без предполагаемых связей.
// Обновление сервера не должно требовать нового скана: при запуске
// (после миграций) типы пересчитываются по сохранённым метаданным,
// а шлюз берётся из последнего скана либо из резервных источников.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"

	"github.com/ShkodnikAI/NetAtlas/internal/devkind"
	"github.com/ShkodnikAI/NetAtlas/internal/gateway"
	"github.com/ShkodnikAI/NetAtlas/internal/model"
	"github.com/ShkodnikAI/NetAtlas/server/audit"
)

// RecomputeKinds пересчитывает kind_auto всех устройств по
// сохранённым метаданным (vendor, hostname, имена, MAC, адрес шлюза)
// и обновляет kind там, где он был автоматическим. Ручной тип
// владельца (kind_manual = 1) и SNMP-факт коммутатора (kind =
// 'switch', классификатор 'switch' не выводит) не трогаются.
// Возвращает число устройств, у которых изменился kind.
//
// Вызывается при каждом открытии базы (Open), поэтому запись идёт в
// одной транзакции с единственной записью аудита: повторный запуск
// на пересчитанной базе не меняет ничего.
func (s *Store) RecomputeKinds(ctx context.Context) (int, error) {
	// Шлюзы до транзакции: соединение в пуле одно, запросы мимо
	// транзакции при открытой tx заблокировались бы навсегда.
	gateways := map[string]bool{}
	for _, gw := range s.effectiveGateways(ctx) {
		gateways[gw.String()] = true
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("store: пересчёт типов: транзакция: %w", err)
	}
	defer tx.Rollback()

	// Имена и адреса одним запросом на таблицу: пересчёт идёт при
	// каждом старте, поэтому без запроса на устройство.
	names := map[string][]string{}
	nameRows, err := tx.QueryContext(ctx,
		`SELECT device_id, name FROM device_names ORDER BY device_id, seen`)
	if err != nil {
		return 0, fmt.Errorf("store: пересчёт типов: имена: %w", err)
	}
	for nameRows.Next() {
		var id, name string
		if err := nameRows.Scan(&id, &name); err != nil {
			nameRows.Close()
			return 0, fmt.Errorf("store: пересчёт типов: имя: %w", err)
		}
		names[id] = append(names[id], name)
	}
	nameRows.Close()
	if err := nameRows.Err(); err != nil {
		return 0, fmt.Errorf("store: пересчёт типов: имена: %w", err)
	}

	deviceIPs := map[string]map[string]bool{}
	ipRows, err := tx.QueryContext(ctx, `SELECT device_id, ip FROM device_ips`)
	if err != nil {
		return 0, fmt.Errorf("store: пересчёт типов: адреса: %w", err)
	}
	for ipRows.Next() {
		var id, ip string
		if err := ipRows.Scan(&id, &ip); err != nil {
			ipRows.Close()
			return 0, fmt.Errorf("store: пересчёт типов: адрес: %w", err)
		}
		if deviceIPs[id] == nil {
			deviceIPs[id] = map[string]bool{}
		}
		deviceIPs[id][ip] = true
	}
	ipRows.Close()
	if err := ipRows.Err(); err != nil {
		return 0, fmt.Errorf("store: пересчёт типов: адреса: %w", err)
	}

	devRows, err := tx.QueryContext(ctx,
		`SELECT id, kind, kind_auto, kind_manual, hostname, vendor FROM devices`)
	if err != nil {
		return 0, fmt.Errorf("store: пересчёт типов: устройства: %w", err)
	}
	type update struct {
		id          string
		kindAuto    string
		kind        string
		kindChanged bool
	}
	updates := make([]update, 0, 16)
	for devRows.Next() {
		var id, kind, kindAuto, hostname, vendor string
		var kindManual bool
		if err := devRows.Scan(&id, &kind, &kindAuto, &kindManual, &hostname, &vendor); err != nil {
			devRows.Close()
			return 0, fmt.Errorf("store: пересчёт типов: устройство: %w", err)
		}
		in := devkind.Input{Vendor: vendor, Hostname: hostname, Names: names[id], MAC: id}
		for ip := range deviceIPs[id] {
			if gateways[ip] {
				in.IsGateway = true
				break
			}
		}
		auto := devkind.Classify(in)
		newKind := auto
		switch {
		case kindManual:
			// Ручной тип владельца сильнее классификатора.
			newKind = kind
		case kind == model.NodeKindSwitch:
			// SNMP-факт сильнее предположения (как в SaveScan).
			newKind = kind
		}
		updates = append(updates, update{
			id:          id,
			kindAuto:    auto,
			kind:        newKind,
			kindChanged: kind != newKind,
		})
	}
	devRows.Close()
	if err := devRows.Err(); err != nil {
		return 0, fmt.Errorf("store: пересчёт типов: устройства: %w", err)
	}

	changed := 0
	for _, u := range updates {
		if _, err := tx.ExecContext(ctx,
			`UPDATE devices SET kind_auto = ?, kind = ? WHERE id = ?`,
			u.kindAuto, u.kind, u.id); err != nil {
			return 0, fmt.Errorf("store: пересчёт типов: обновление %s: %w", u.id, err)
		}
		if u.kindChanged {
			changed++
		}
	}
	// Аудит только при фактической смене типов: запись на каждый
	// старт без изменений завалила бы журнал (перезапуски — не
	// события). Деталь — число пересчитанных и изменившихся типов,
	// без перечня устройств.
	if changed > 0 {
		detailJSON := fmt.Sprintf(`{"updated":%d,"kinds_changed":%d}`, len(updates), changed)
		if _, err := audit.Append(ctx, tx, audit.Entry{
			Actor:  "server",
			Action: "recompute_kinds",
			Target: "devices",
			Result: "ok",
			Detail: detailJSON,
		}); err != nil {
			return 0, fmt.Errorf("store: пересчёт типов: аудит: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("store: пересчёт типов: фиксация: %w", err)
	}
	return changed, nil
}

// effectiveGateways — шлюзы по умолчанию для предполагаемых связей и
// пересчёта типов (NR-034): шлюзы последнего скана; если их нет —
// резерв из подсетей последнего скана:
//   - маршруты по умолчанию хоста сервера (internal/gateway) внутри
//     известных подсетей;
//   - первый адрес подсети, у которого есть устройство (шлюз «.1»).
//
// Подсетей нет — резерва нет: угадывать шлюз без границ нельзя.
func (s *Store) effectiveGateways(ctx context.Context) []netip.Addr {
	var gwRaw, subRaw string
	err := s.db.QueryRowContext(ctx,
		`SELECT gateways, subnets FROM scans ORDER BY id DESC LIMIT 1`).
		Scan(&gwRaw, &subRaw)
	if err != nil {
		return nil
	}
	gws := parseAddrs(gwRaw)
	if len(gws) > 0 {
		return gws
	}
	subnets := parsePrefixes(subRaw)
	if len(subnets) == 0 {
		return nil
	}

	seen := map[string]bool{}
	out := make([]netip.Addr, 0, 2)
	add := func(a netip.Addr) {
		if !a.IsValid() || seen[a.String()] {
			return
		}
		seen[a.String()] = true
		out = append(out, a)
	}
	// Маршруты хоста внутри известных подсетей (кэш таблицы ОС).
	for _, gw := range s.hostGateways() {
		for _, p := range subnets {
			if p.Contains(gw) {
				add(gw)
				break
			}
		}
	}
	// Первый адрес подсети, за которым стоит устройство: в домашних
	// и офисных сетях шлюз почти всегда «.1», а устройство на этом
	// адресе уже найдено сканом.
	for _, p := range subnets {
		if p.Bits() >= 31 {
			continue // /31, /32 — адреса шлюзов не имеют
		}
		first := p.Masked().Addr().Next()
		var devID string
		if err := s.db.QueryRowContext(ctx,
			`SELECT device_id FROM device_ips WHERE ip = ? LIMIT 1`,
			first.String()).Scan(&devID); err != nil || devID == "" {
			continue
		}
		add(first)
	}
	return out
}

// hostGateways — адреса шлюзов по умолчанию хоста сервера. Таблица
// маршрутов читается один раз на открытие базы (s.gatewayOnce).
// Ошибка чтения (нет прав, нет /proc) — пустой список, резерв просто
// не добавляет маршрутных шлюзов.
func (s *Store) hostGateways() []netip.Addr {
	s.gatewayOnce.Do(func() {
		gws, err := gatewayProbe()
		if err != nil || len(gws) == 0 {
			return
		}
		s.gatewayCache = uniqAddrs(gws)
	})
	return s.gatewayCache
}

// gatewayProbe — точка чтения таблицы маршрутов; переменная для
// тестов (по умолчанию — internal/gateway.Default).
var gatewayProbe = gateway.Default

// parseAddrs — JSON-массив адресов без повторов и невалидных.
func parseAddrs(raw string) []netip.Addr {
	if raw == "" {
		return nil
	}
	var addrs []netip.Addr
	if err := json.Unmarshal([]byte(raw), &addrs); err != nil {
		return nil
	}
	return uniqAddrs(addrs)
}

// uniqAddrs — валидные адреса без повторов.
func uniqAddrs(addrs []netip.Addr) []netip.Addr {
	seen := map[string]bool{}
	out := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		if !a.IsValid() || seen[a.String()] {
			continue
		}
		seen[a.String()] = true
		out = append(out, a)
	}
	return out
}

// parsePrefixes — JSON-массив подсетей (строки CIDR) в префиксы.
func parsePrefixes(raw string) []netip.Prefix {
	if raw == "" {
		return nil
	}
	var strs []string
	if err := json.Unmarshal([]byte(raw), &strs); err != nil {
		return nil
	}
	out := make([]netip.Prefix, 0, len(strs))
	seen := map[string]bool{}
	for _, s := range strs {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			continue
		}
		p = p.Masked()
		if seen[p.String()] {
			continue
		}
		seen[p.String()] = true
		out = append(out, p)
	}
	return out
}
