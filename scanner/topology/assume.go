// Предполагаемые связи «устройство — шлюз» (NR-032 п.3): если у
// подсети нет ни одной связи из LLDP/FDB, карта рисует звезду к
// шлюзу. Данные о коммутаторе отсутствуют — связь помечается как
// предположение (source «assumed», на карте пунктир) и в базу не
// пишется: она вычисляется при отдаче графа и исчезает, как только
// появляются связи из LLDP/FDB.
package topology

import (
	"sort"

	"github.com/ShkodnikAI/NetAtlas/internal/model"
)

// AssumedLinks возвращает предполагаемые связи «шлюз — устройство»:
//   - links не содержит ни одной связи lldp/fdb/inferred (то есть по
//     сети нет ни одного фактического соседства из SNMP-опроса);
//   - каждая связь соединяет узел шлюза с устройством-сканером
//     (MAC-узел), кроме самих шлюзов;
//   - связи, чьи концы уже есть в links (например ручные), не
//     дублируются;
//   - результат отсортирован и детерминирован: порядок входных
//     срезов на итог не влияет.
//
// deviceIDs — идентификаторы устройств-сканеров (MAC), gatewayIDs —
// идентификаторы узлов шлюзов (MAC устройства или «ip:адрес»).
func AssumedLinks(deviceIDs, gatewayIDs []string, links []model.Link) []model.Link {
	for _, l := range links {
		switch l.Source {
		case model.LinkSourceLLDP, model.LinkSourceFDB, model.LinkSourceInferred:
			return nil // есть фактические данные о коммутации
		}
	}
	gateways := sortedUnique(gatewayIDs)
	if len(gateways) == 0 {
		return nil // шлюзы неизвестны — предполагать нечего
	}
	gwSet := make(map[string]bool, len(gateways))
	for _, g := range gateways {
		gwSet[g] = true
	}
	existing := make(map[linkKey]bool, len(links))
	for _, l := range links {
		existing[linkKey{l.A, l.APort, l.B, l.BPort}] = true
		existing[linkKey{l.B, l.BPort, l.A, l.APort}] = true
	}
	devices := sortedUnique(deviceIDs)
	out := make([]model.Link, 0, len(devices))
	for _, dev := range devices {
		if gwSet[dev] {
			continue // шлюз сам себе не соединяется
		}
		for _, gw := range gateways {
			l := normalizedLink(gw, dev, model.LinkSourceAssumed)
			if existing[lk(l)] {
				continue
			}
			existing[lk(l)] = true
			out = append(out, l)
		}
	}
	sort.Slice(out, func(i, j int) bool { return compareLinks(out[i], out[j]) < 0 })
	return out
}

// sortedUnique — непустые идентификаторы без повторов по возрастанию.
func sortedUnique(ids []string) []string {
	seen := make(map[string]bool, len(ids))
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// normalizedLink — связь с меньшим ID на конце A (как в addLink).
func normalizedLink(a, b, source string) model.Link {
	if b < a {
		a, b = b, a
	}
	return model.Link{A: a, B: b, Source: source}
}

func lk(l model.Link) linkKey {
	return linkKey{l.A, l.APort, l.B, l.BPort}
}
