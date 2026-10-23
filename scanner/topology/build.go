// Package topology — построение графа топологии из уже собранных
// данных: устройства сканера (ARP/ping, ID = MAC) и результаты
// SNMP-опроса (sysName, порты, FDB, LLDP). Сети пакет не касается:
// Build — чистая функция без запросов, файлов и глобального
// состояния, входные данные только читаются.
//
// Правила (NR-019):
//   - цель SNMP без ошибки — узел «switch» (ID устройства, если IP
//     цели есть у какого-то устройства, иначе ip:адрес);
//   - LLDP-сосед с ChassisID в виде MAC — связь «lldp» к узлу с этим
//     MAC (нет узла — создаётся «unknown»); связь, увиденная с обеих
//     сторон, записывается один раз;
//   - порт с LLDP-соседом — транзитный: его MAC-адреса прямых связей
//     не образуют (они за соседом);
//   - порт без LLDP и с одним MAC — связь «fdb» к устройству (или
//     «unknown»);
//   - порт без LLDP и с двумя и более MAC — неуправляемый коммутатор:
//     узел «cloud», связь «inferred» от коммутатора и связи «fdb» от
//     облака к каждому устройству;
//   - собственные MAC коммутаторов в FDB пропускаются;
//   - устройства без связей остаются в графе узлами «device».
//
// Уточнения NR-021:
//   - MAC-адреса всех ответивших коммутаторов собираются до обработки
//     таблиц MAC: собственный MAC коммутатора пропускается в таблице
//     любого другого коммутатора независимо от порядка целей;
//   - MAC, видимый в таблицах нескольких коммутаторов, даёт прямую
//     связь «fdb» только на «ближайшем» порту — там, где на порту
//     наименьшее число различных MAC (при равенстве — меньший ID
//     коммутатора, затем меньшее имя порта); на остальных коммутаторах
//     он считается «за соседом» и в связь не идёт;
//   - порт, на котором не осталось «своих» MAC, но есть чужие, —
//     транзитный: связь «inferred» к коммутатору, на котором эти MAC
//     найдены ближе (если связи «lldp» между ними ещё нет).
//
// Результат детерминирован: узлы отсортированы по ID, связи — по
// (A, APort, B, BPort); порядок входных срезов на итог не влияет.
package topology

import (
	"sort"

	"github.com/ShkodnikAI/NetAtlas/internal/model"
	"github.com/ShkodnikAI/NetAtlas/scanner/snmp"
)

// Build собирает граф топологии из устройств сканера и результатов
// SNMP-опроса. Мусорные и пустые записи пропускаются без паники.
func Build(devices []model.Device, results []snmp.TargetResult) model.Topology {
	b := newBuilder(devices)
	targets := b.sortedTargets(results)
	// NR-021: MAC коммутаторов известны до обработки таблиц MAC,
	// поэтому они пропускаются в FDB любого коммутатора независимо
	// от порядка целей (сортировка целей не должна влиять на то,
	// чей MAC уже «увиден»).
	b.collectSwitchMACs(targets)
	for _, r := range targets {
		if r.Error != "" {
			continue // цель не ответила: ни узла, ни связей из её данных
		}
		swID := b.switchNode(r)
		if swID == "" {
			continue
		}
		b.lldpLinks(swID, r)
	}
	b.buildFDBLinks(targets)
	b.remainingDevices()
	return b.assemble()
}

// builder — накопительное состояние одного вызова Build.
type builder struct {
	nodes map[string]model.Node
	links map[linkKey]model.Link
	// deviceLabel — подписи устройств по MAC (ID).
	deviceLabel map[string]string
	// ipToDevice — IP устройства → его ID; при конфликте выбирается
	// меньший ID (детерминированность независимо от порядка входа).
	ipToDevice map[string]string
	// switchMACs — MAC-адреса, ставшие ID узлов-коммутаторов; в FDB
	// они пропускаются. Заполняются до обработки таблиц MAC.
	switchMACs map[string]bool
}

// place — позиция MAC-адреса в таблице коммутатора.
type place struct {
	swID, port string
}

// linkKey — нормализованный ключ связи для дедупликации: одна и та
// же связь, увиденная с обеих сторон, даёт одинаковый ключ.
type linkKey struct {
	a, aPort, b, bPort string
}

func newBuilder(devices []model.Device) *builder {
	b := &builder{
		nodes:       make(map[string]model.Node),
		links:       make(map[linkKey]model.Link),
		deviceLabel: make(map[string]string),
		ipToDevice:  make(map[string]string),
		switchMACs:  make(map[string]bool),
	}
	for _, d := range devices {
		if d.ID == "" {
			continue
		}
		if _, ok := b.deviceLabel[d.ID]; !ok {
			b.deviceLabel[d.ID] = deviceLabel(d)
		}
		for _, ip := range d.IPs {
			key := ip.String()
			if old, ok := b.ipToDevice[key]; !ok || d.ID < old {
				b.ipToDevice[key] = d.ID
			}
		}
	}
	return b
}

// deviceLabel — подпись устройства: hostname, первое имя, иначе MAC.
func deviceLabel(d model.Device) string {
	if d.Hostname != "" {
		return d.Hostname
	}
	for _, n := range d.Names {
		if n.Name != "" {
			return n.Name
		}
	}
	return d.ID
}

// sortedTargets — результаты без невалидных целей, упорядоченные по
// адресу: порядок входного среза не влияет на итог.
func (b *builder) sortedTargets(results []snmp.TargetResult) []snmp.TargetResult {
	out := make([]snmp.TargetResult, 0, len(results))
	for _, r := range results {
		if r.Target.IsValid() {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Target.Compare(out[j].Target) < 0
	})
	return out
}

// collectSwitchMACs собирает MAC-адреса всех ответивших коммутаторов
// (по IP цели → устройство) до обработки таблиц MAC.
func (b *builder) collectSwitchMACs(targets []snmp.TargetResult) {
	for _, r := range targets {
		if r.Error != "" {
			continue // неответившая цель коммутатором не считается
		}
		if devID, ok := b.ipToDevice[r.Target.String()]; ok {
			b.switchMACs[devID] = true
		}
	}
}

// switchID — ID узла коммутатора для цели: ID устройства, если IP
// цели есть у какого-то устройства, иначе ip:адрес.
func (b *builder) switchID(r snmp.TargetResult) string {
	ip := r.Target.String()
	if devID, ok := b.ipToDevice[ip]; ok {
		return devID
	}
	return "ip:" + ip
}

// switchNode создаёт узел коммутатора для цели без ошибки и
// возвращает его ID; пустая строка — узел не создан.
func (b *builder) switchNode(r snmp.TargetResult) string {
	id := b.switchID(r)
	label := r.SysName
	if label == "" {
		label = r.Target.String()
	}
	if n, ok := b.nodes[id]; ok {
		if n.Kind != model.NodeKindSwitch {
			// Узел создан заранее как device/unknown (по LLDP или FDB):
			// это тот же физический коммутатор — вид меняется на switch.
			b.nodes[id] = model.Node{ID: id, Kind: model.NodeKindSwitch, Label: label}
		}
		return id // две цели одного коммутатора — узел уже есть
	}
	b.nodes[id] = model.Node{ID: id, Kind: model.NodeKindSwitch, Label: label}
	return id
}

// lldpLinks добавляет связи «lldp» коммутатора с соседями, чей
// ChassisID — MAC-адрес. Связь, увиденная с обеих сторон, даёт один
// ключ и записывается один раз.
func (b *builder) lldpLinks(swID string, r snmp.TargetResult) {
	for _, n := range r.LLDP {
		mac, err := model.NormalizeMAC(n.ChassisID)
		if err != nil {
			continue // сосед без MAC-идентификатора связи не даёт
		}
		b.addLink(swID, n.LocalPort, b.endpoint(mac), n.RemotePort, model.LinkSourceLLDP)
	}
}

// buildFDBLinks превращает таблицы MAC всех коммутаторов в связи:
// транзитные порты (с LLDP-соседом) пропускаются, у каждого MAC
// выбирается «ближайшее» место, порт с одним своим MAC — связь «fdb»,
// порт с несколькими своими MAC — «облако» неуправляемого коммутатора,
// порт без своих MAC, но с чужими — транзит «inferred».
func (b *builder) buildFDBLinks(targets []snmp.TargetResult) {
	// Транзитные порты — порты с LLDP-соседом этого коммутатора.
	transit := make(map[string]map[string]bool)
	for _, r := range targets {
		if r.Error != "" || len(r.LLDP) == 0 {
			continue
		}
		ports := make(map[string]bool, len(r.LLDP))
		for _, n := range r.LLDP {
			ports[n.LocalPort] = true
		}
		transit[b.switchID(r)] = ports
	}

	// Наблюдения MAC по не-транзитным портам каждого коммутатора:
	// дедупликация, отбрасывание мусора и MAC коммутаторов.
	obs := make(map[string]map[string][]string)
	for _, r := range targets {
		if r.Error != "" {
			continue
		}
		swID := b.switchID(r)
		for _, e := range r.FDB {
			mac, err := model.NormalizeMAC(e.MAC)
			if err != nil || b.switchMACs[mac] {
				continue
			}
			if transit[swID][e.Port] {
				continue // MAC за LLDP-соседом
			}
			ports, ok := obs[swID]
			if !ok {
				ports = make(map[string][]string)
				obs[swID] = ports
			}
			ports[e.Port] = appendUnique(ports[e.Port], mac)
		}
	}

	// Ближайшее место каждого MAC (NR-021): прямая связь строится
	// только там, где на порту наименьшее число различных MAC; при
	// равенстве — меньший ID коммутатора, затем меньшее имя порта.
	counts := make(map[place]int)
	byMAC := make(map[string][]place)
	for swID, ports := range obs {
		for port, macs := range ports {
			counts[place{swID, port}] = len(macs)
			for _, mac := range macs {
				byMAC[mac] = append(byMAC[mac], place{swID, port})
			}
		}
	}
	better := func(a, c place) bool {
		if counts[a] != counts[c] {
			return counts[a] < counts[c]
		}
		if a.swID != c.swID {
			return a.swID < c.swID
		}
		return a.port < c.port
	}
	nearest := make(map[string]place, len(byMAC))
	for mac, places := range byMAC {
		best := places[0]
		for _, p := range places[1:] {
			if better(p, best) {
				best = p
			}
		}
		nearest[mac] = best
	}

	// Раскладка портов по «своим» MAC (тем, чьё ближайшее место здесь).
	swIDs := make([]string, 0, len(obs))
	for swID := range obs {
		swIDs = append(swIDs, swID)
	}
	sort.Strings(swIDs)
	for _, swID := range swIDs {
		ports := obs[swID]
		names := make([]string, 0, len(ports))
		for port := range ports {
			names = append(names, port)
		}
		sort.Strings(names)
		for _, port := range names {
			macs := ports[port]
			own := make([]string, 0, len(macs))
			for _, mac := range macs {
				if p := nearest[mac]; p.swID == swID && p.port == port {
					own = append(own, mac)
				}
			}
			switch {
			case len(own) == 1:
				b.addLink(swID, port, b.endpoint(own[0]), "", model.LinkSourceFDB)
			case len(own) >= 2:
				cloudID := "cloud:" + swID + ":" + port
				if _, ok := b.nodes[cloudID]; !ok {
					b.nodes[cloudID] = model.Node{
						ID:    cloudID,
						Kind:  model.NodeKindCloud,
						Label: "неуправляемая сеть (" + port + ")",
					}
				}
				b.addLink(swID, port, cloudID, "", model.LinkSourceInferred)
				for _, mac := range own {
					b.addLink(cloudID, "", b.endpoint(mac), "", model.LinkSourceFDB)
				}
			default:
				// Своих MAC не осталось, но порт видел чужие: MAC за
				// соседом — порт транзитный.
				b.transitLink(swID, port, macs, nearest)
			}
		}
	}
}

// transitLink добавляет связь «inferred» от порта коммутатора, на
// котором не осталось «своих» MAC, к коммутатору, на котором эти MAC
// найдены ближе, — если тот один и связи «lldp» между ними ещё нет.
func (b *builder) transitLink(swID, port string, macs []string, nearest map[string]place) {
	target := ""
	for _, mac := range macs {
		p, ok := nearest[mac]
		if !ok || p.swID == swID {
			continue // ближайшее место здесь или его нет
		}
		if target == "" {
			target = p.swID
		} else if target != p.swID {
			return // MAC порта уходят к разным коммутаторам: связи не рисуем
		}
	}
	if target == "" || b.lldpBetween(swID, target) {
		return
	}
	b.addLink(swID, port, target, "", model.LinkSourceInferred)
}

// lldpBetween проверяет, есть ли уже связь «lldp» между двумя узлами.
func (b *builder) lldpBetween(a, b2 string) bool {
	for _, l := range b.links {
		if l.Source != model.LinkSourceLLDP {
			continue
		}
		if (l.A == a && l.B == b2) || (l.A == b2 && l.B == a) {
			return true
		}
	}
	return false
}

// remainingDevices добавляет устройства, ещё не ставшие узлами:
// коммутаторы уже в графе, остальные остаются узлами «device».
func (b *builder) remainingDevices() {
	ids := make([]string, 0, len(b.deviceLabel))
	for id := range b.deviceLabel {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if _, ok := b.nodes[id]; !ok {
			b.nodes[id] = model.Node{ID: id, Kind: model.NodeKindDevice, Label: b.deviceLabel[id]}
		}
	}
}

// assemble собирает топологию: узлы по ID, связи по
// (A, APort, B, BPort).
func (b *builder) assemble() model.Topology {
	topo := model.NewTopology()
	for _, n := range b.nodes {
		topo.Nodes = append(topo.Nodes, n)
	}
	for _, l := range b.links {
		topo.Links = append(topo.Links, l)
	}
	sort.Slice(topo.Nodes, func(i, j int) bool { return topo.Nodes[i].ID < topo.Nodes[j].ID })
	sort.Slice(topo.Links, func(i, j int) bool { return compareLinks(topo.Links[i], topo.Links[j]) < 0 })
	return topo
}

// compareLinks сравнивает связи по (A, APort, B, BPort).
func compareLinks(a, bb model.Link) int {
	switch {
	case a.A != bb.A:
		if a.A < bb.A {
			return -1
		}
		return 1
	case a.APort != bb.APort:
		if a.APort < bb.APort {
			return -1
		}
		return 1
	case a.B != bb.B:
		if a.B < bb.B {
			return -1
		}
		return 1
	case a.BPort != bb.BPort:
		if a.BPort < bb.BPort {
			return -1
		}
		return 1
	}
	return 0
}

// addLink вставляет связь с нормализацией порядка концов: конец A —
// с меньшим ID. Повторная вставка той же связи игнорируется.
func (b *builder) addLink(a, aPort, b2, bPort, source string) {
	if a == b2 {
		return // самосвязь не имеет смысла на карте
	}
	if b2 < a {
		a, aPort, b2, bPort = b2, bPort, a, aPort
	}
	key := linkKey{a, aPort, b2, bPort}
	if _, ok := b.links[key]; ok {
		return
	}
	b.links[key] = model.Link{A: a, APort: aPort, B: b2, BPort: bPort, Source: source}
}

// endpoint возвращает ID узла для MAC-адреса: существующий узел,
// устройство сканера или новый узел «unknown».
func (b *builder) endpoint(mac string) string {
	if _, ok := b.nodes[mac]; ok {
		return mac
	}
	if label, ok := b.deviceLabel[mac]; ok {
		b.nodes[mac] = model.Node{ID: mac, Kind: model.NodeKindDevice, Label: label}
		return mac
	}
	b.nodes[mac] = model.Node{ID: mac, Kind: model.NodeKindUnknown, Label: mac}
	return mac
}

// appendUnique добавляет s в срез, если его там ещё нет.
func appendUnique(list []string, s string) []string {
	for _, v := range list {
		if v == s {
			return list
		}
	}
	return append(list, s)
}
