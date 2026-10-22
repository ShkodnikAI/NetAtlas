package snmp

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strconv"

	"github.com/ShkodnikAI/NetAtlas/internal/model"
)

// OID-деревья (только чтение). Индексы таблиц разбираются из суффикса
// OID, значения — из PDU.
const (
	oidSysDescr = "1.3.6.1.2.1.1.1.0" // SNMPv2-MIB::sysDescr.0
	oidSysName  = "1.3.6.1.2.1.1.5.0" // SNMPv2-MIB::sysName.0

	oidIfName  = "1.3.6.1.2.1.31.1.1.1.1" // IF-MIB::ifName (индекс — ifIndex)
	oidIfDescr = "1.3.6.1.2.1.2.2.1.2"    // IF-MIB::ifDescr (запасной источник имён)

	oidQBridgeFdbPort  = "1.3.6.1.2.1.17.7.1.2.2.1.3" // Q-BRIDGE-MIB::dot1qTpFdbPort (индекс: fdbId + 6 байт MAC)
	oidBridgeFdbPort   = "1.3.6.1.2.1.17.4.3.1.2"     // BRIDGE-MIB::dot1dTpFdbPort (индекс: 6 байт MAC)
	oidBridgePortIfIdx = "1.3.6.1.2.1.17.1.4.1.2"     // BRIDGE-MIB::dot1dBasePortIfIndex (индекс: номер порта)

	oidLldpChassisSubtype = "1.0.8802.1.1.2.1.4.1.1.4" // LLDP-MIB::lldpRemChassisIdSubtype
	oidLldpChassisId      = "1.0.8802.1.1.2.1.4.1.1.5" // LLDP-MIB::lldpRemChassisId
	oidLldpPortSubtype    = "1.0.8802.1.1.2.1.4.1.1.6" // LLDP-MIB::lldpRemPortIdSubtype
	oidLldpPortId         = "1.0.8802.1.1.2.1.4.1.1.7" // LLDP-MIB::lldpRemPortId
	oidLldpSysName        = "1.0.8802.1.1.2.1.4.1.1.9" // LLDP-MIB::lldpRemSysName
)

// Подтипы идентификаторов LLDP, нужные для декодирования значений.
const (
	lldpSubtypeMAC     = 4 // chassis: macAddress
	lldpSubtypePortMAC = 3 // port: macAddress
)

// Port — порт цели: ifIndex и имя (ifName; если пусто — ifDescr).
type Port struct {
	Index int    `json:"index"`
	Name  string `json:"name"`
}

// Result — собранное с одной цели: система, порты, FDB и LLDP-соседи.
// Срезы непустые (не nil), чтобы в JSON были [].
type Result struct {
	SysName  string
	SysDescr string
	Ports    []Port
	FDB      []model.FdbEntry
	LLDP     []model.LldpNeighbor
}

// TargetResult — запись по цели для JSON-вывода. Неответившая цель
// даёт запись с полем error (текст ошибки; учётные данные туда не
// входят — они никуда не пишутся).
type TargetResult struct {
	Target   netip.Addr           `json:"target"`
	SysName  string               `json:"sys_name,omitempty"`
	SysDescr string               `json:"sys_descr,omitempty"`
	Ports    []Port               `json:"ports"`
	FDB      []model.FdbEntry     `json:"fdb"`
	LLDP     []model.LldpNeighbor `json:"lldp"`
	Error    string               `json:"error,omitempty"`
}

// NewTargetResult возвращает пустую запись цели с непустыми срезами.
func NewTargetResult(t netip.Addr) TargetResult {
	return TargetResult{Target: t, Ports: []Port{}, FDB: []model.FdbEntry{}, LLDP: []model.LldpNeighbor{}}
}

// Fill переносит собранное из Result в запись цели.
func (tr *TargetResult) Fill(r Result) {
	tr.SysName = r.SysName
	tr.SysDescr = r.SysDescr
	tr.Ports = r.Ports
	tr.FDB = r.FDB
	tr.LLDP = r.LLDP
}

// Collect собирает данные с одной цели через walker: sysName и
// sysDescr; порты из ifName (пусто — ifDescr); таблицу MAC → порт из
// Q-BRIDGE dot1qTpFdbPort, при пустом ответе — запасной BRIDGE
// dot1dTpFdbPort с переводом номера порта в ifIndex; соседей LLDP.
// Мусорные и неполные строки пропускаются без паники. Ошибка walker
// прерывает сбор (цель не ответила).
func Collect(ctx context.Context, w Walker) (Result, error) {
	res := Result{Ports: []Port{}, FDB: []model.FdbEntry{}, LLDP: []model.LldpNeighbor{}}
	if w == nil {
		return Result{}, fmt.Errorf("snmp: walker не задан")
	}

	pdus, err := w.Get(ctx, oidSysDescr, oidSysName)
	if err != nil {
		return Result{}, fmt.Errorf("snmp: система: %w", err)
	}
	for _, p := range pdus {
		if b, ok := pduBytes(p); ok {
			switch p.OID {
			case oidSysDescr:
				res.SysDescr = printableBytes(b)
			case oidSysName:
				res.SysName = printableBytes(b)
			}
		}
	}

	names, err := collectPorts(ctx, w)
	if err != nil {
		return Result{}, fmt.Errorf("snmp: порты: %w", err)
	}
	res.Ports = sortedPorts(names)

	if res.FDB, err = collectFDB(ctx, w, names); err != nil {
		return Result{}, fmt.Errorf("snmp: fdb: %w", err)
	}
	if res.LLDP, err = collectLLDP(ctx, w, names); err != nil {
		return Result{}, fmt.Errorf("snmp: lldp: %w", err)
	}
	return res, nil
}

// collectPorts читает ifIndex → имя из ifName; если таблица пуста —
// из ifDescr.
func collectPorts(ctx context.Context, w Walker) (map[int]string, error) {
	names := make(map[int]string)
	err := w.Walk(ctx, oidIfName, func(p PDU) error {
		addPortName(names, p, oidIfName)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(names) > 0 {
		return names, nil
	}
	err = w.Walk(ctx, oidIfDescr, func(p PDU) error {
		addPortName(names, p, oidIfDescr)
		return nil
	})
	return names, err
}

func addPortName(names map[int]string, p PDU, prefix string) {
	idx, ok := oidIndex(p.OID, prefix)
	if !ok || len(idx) != 1 {
		return
	}
	b, ok := pduBytes(p)
	if !ok {
		return
	}
	if s := printableBytes(b); s != "" {
		names[int(idx[0])] = s
	}
}

func sortedPorts(names map[int]string) []Port {
	ports := make([]Port, 0, len(names))
	for i, n := range names {
		ports = append(ports, Port{Index: i, Name: n})
	}
	sort.Slice(ports, func(i, j int) bool { return ports[i].Index < ports[j].Index })
	return ports
}

// portName переводит номер порта в имя; без имени — номер строкой.
func portName(p int, names map[int]string) string {
	if n, ok := names[p]; ok {
		return n
	}
	return strconv.Itoa(p)
}

// collectFDB собирает таблицу MAC → порт. Сначала Q-BRIDGE
// (значение порта — ifIndex); если таблица пуста — BRIDGE: значение
// dot1dTpFdbPort — номер порта моста, он переводится в ifIndex через
// dot1dBasePortIfIndex.
func collectFDB(ctx context.Context, w Walker, names map[int]string) ([]model.FdbEntry, error) {
	entries := make([]model.FdbEntry, 0)
	err := w.Walk(ctx, oidQBridgeFdbPort, func(p PDU) error {
		idx, ok := oidIndex(p.OID, oidQBridgeFdbPort)
		if !ok || len(idx) != 7 {
			return nil
		}
		mac, ok := macFromOIDParts(idx[1:])
		if !ok {
			return nil
		}
		port, ok := pduInt(p)
		if !ok || port <= 0 {
			return nil
		}
		entries = append(entries, model.FdbEntry{MAC: mac, Port: portName(port, names)})
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(entries) > 0 {
		sortFDB(entries)
		return entries, nil
	}

	// Запасной BRIDGE: номер порта моста → ifIndex.
	baseToIfIdx := make(map[int]int)
	err = w.Walk(ctx, oidBridgePortIfIdx, func(p PDU) error {
		idx, ok := oidIndex(p.OID, oidBridgePortIfIdx)
		if !ok || len(idx) != 1 {
			return nil
		}
		ifIdx, ok := pduInt(p)
		if !ok || ifIdx <= 0 {
			return nil
		}
		baseToIfIdx[int(idx[0])] = ifIdx
		return nil
	})
	if err != nil {
		return nil, err
	}
	err = w.Walk(ctx, oidBridgeFdbPort, func(p PDU) error {
		idx, ok := oidIndex(p.OID, oidBridgeFdbPort)
		if !ok || len(idx) != 6 {
			return nil
		}
		mac, ok := macFromOIDParts(idx)
		if !ok {
			return nil
		}
		base, ok := pduInt(p)
		if !ok || base <= 0 {
			return nil
		}
		port := base
		if ifIdx, ok := baseToIfIdx[base]; ok {
			port = ifIdx
		}
		entries = append(entries, model.FdbEntry{MAC: mac, Port: portName(port, names)})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sortFDB(entries)
	return entries, nil
}

func sortFDB(entries []model.FdbEntry) {
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].MAC != entries[j].MAC {
			return entries[i].MAC < entries[j].MAC
		}
		return entries[i].Port < entries[j].Port
	})
}

// lldpKey — индекс строки lldpRemTable: timeMark, локальный порт,
// индекс соседа.
type lldpKey struct{ tm, lp, idx uint64 }

// collectLLDP собирает соседей LLDP: подтипы и значения chassis/port
// объединяются по индексу строки, локальный порт переводится в имя
// через ifName.
func collectLLDP(ctx context.Context, w Walker, names map[int]string) ([]model.LldpNeighbor, error) {
	var (
		chassisSub = make(map[lldpKey]int)
		chassisID  = make(map[lldpKey][]byte)
		portSub    = make(map[lldpKey]int)
		portID     = make(map[lldpKey][]byte)
		sysName    = make(map[lldpKey]string)
		keys       []lldpKey
		seen       = make(map[lldpKey]bool)
	)
	add := func(m map[lldpKey]bool, k lldpKey) {
		if !m[k] {
			m[k] = true
			keys = append(keys, k)
		}
	}
	steps := []struct {
		oid  string
		keep func(p PDU, k lldpKey)
	}{
		{oidLldpChassisSubtype, func(p PDU, k lldpKey) {
			if v, ok := pduInt(p); ok {
				chassisSub[k] = v
			}
		}},
		{oidLldpChassisId, func(p PDU, k lldpKey) {
			if b, ok := pduBytes(p); ok {
				chassisID[k] = b
			}
		}},
		{oidLldpPortSubtype, func(p PDU, k lldpKey) {
			if v, ok := pduInt(p); ok {
				portSub[k] = v
			}
		}},
		{oidLldpPortId, func(p PDU, k lldpKey) {
			if b, ok := pduBytes(p); ok {
				portID[k] = b
			}
		}},
		{oidLldpSysName, func(p PDU, k lldpKey) {
			if b, ok := pduBytes(p); ok {
				sysName[k] = printableBytes(b)
			}
		}},
	}
	for _, st := range steps {
		err := w.Walk(ctx, st.oid, func(p PDU) error {
			idx, ok := oidIndex(p.OID, st.oid)
			if !ok || len(idx) != 3 {
				return nil
			}
			k := lldpKey{idx[0], idx[1], idx[2]}
			add(seen, k)
			st.keep(p, k)
			return nil
		})
		if err != nil {
			return nil, err
		}
	}

	out := make([]model.LldpNeighbor, 0, len(keys))
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].lp != keys[j].lp {
			return keys[i].lp < keys[j].lp
		}
		if keys[i].idx != keys[j].idx {
			return keys[i].idx < keys[j].idx
		}
		return keys[i].tm < keys[j].tm
	})
	for _, k := range keys {
		ch, okC := chassisID[k]
		pt, okP := portID[k]
		if !okC || !okP {
			continue // неполная строка соседа
		}
		out = append(out, model.LldpNeighbor{
			LocalPort:  portName(int(k.lp), names),
			ChassisID:  decodeID(chassisSub[k], ch, lldpSubtypeMAC),
			RemotePort: decodeID(portSub[k], pt, lldpSubtypePortMAC),
			SysName:    sysName[k],
		})
	}
	return out, nil
}

// decodeID расшифровывает идентификатор LLDP по подтипу: MAC —
// нормализованный адрес, текстовые подтипы — строка, остальное —
// hex-строка. macSubtype — номер подтипа «macAddress» (4 у chassis,
// 3 у port).
func decodeID(subtype int, b []byte, macSubtype int) string {
	if subtype == macSubtype {
		if mac, ok := macFromOIDParts(toOIDParts(b)); ok {
			return mac
		}
	}
	return printableBytes(b)
}

func toOIDParts(b []byte) []uint64 {
	parts := make([]uint64, len(b))
	for i, v := range b {
		parts[i] = uint64(v)
	}
	return parts
}
