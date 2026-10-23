package topology

import (
	"encoding/json"
	"math/rand"
	"net/netip"
	"testing"

	"github.com/ShkodnikAI/NetAtlas/internal/model"
	"github.com/ShkodnikAI/NetAtlas/scanner/snmp"
)

// mustDev — устройство с MAC и (необязательными) IP для фикстур.
func mustDev(t *testing.T, mac string, ips ...string) model.Device {
	t.Helper()
	d, err := model.NewDevice(mac)
	if err != nil {
		t.Fatalf("устройство %s: %v", mac, err)
	}
	for _, s := range ips {
		a, err := netip.ParseAddr(s)
		if err != nil {
			t.Fatalf("IP %s: %v", s, err)
		}
		d.IPs = append(d.IPs, a)
	}
	return d
}

// target — результат SNMP для цели с именем системы.
func target(t *testing.T, ip, sysName string) snmp.TargetResult {
	t.Helper()
	a, err := netip.ParseAddr(ip)
	if err != nil {
		t.Fatalf("цель %s: %v", ip, err)
	}
	tr := snmp.NewTargetResult(a)
	tr.SysName = sysName
	return tr
}

// nodeOf возвращает узел по ID.
func nodeOf(t *testing.T, topo model.Topology, id string) model.Node {
	t.Helper()
	for _, n := range topo.Nodes {
		if n.ID == id {
			return n
		}
	}
	t.Fatalf("узел %q не найден: %+v", id, topo.Nodes)
	return model.Node{}
}

// hasLink проверяет наличие связи между двумя ID (в любом из двух
// направлений — итог нормализован по ID) с портами на концах.
func hasLink(t *testing.T, topo model.Topology, source, id1, port1, id2, port2 string) {
	t.Helper()
	for _, l := range topo.Links {
		if l.Source != source {
			continue
		}
		direct := l.A == id1 && l.APort == port1 && l.B == id2 && l.BPort == port2
		reverse := l.A == id2 && l.APort == port2 && l.B == id1 && l.BPort == port1
		if direct || reverse {
			return
		}
	}
	t.Fatalf("нет связи %s: %s(%s) — %s(%s), есть: %+v", source, id1, port1, id2, port2, topo.Links)
}

// linksBetween считает связи между двумя узлами (в любом направлении),
// независимо от источника.
func linksBetween(topo model.Topology, id1, id2 string) int {
	n := 0
	for _, l := range topo.Links {
		if (l.A == id1 && l.B == id2) || (l.A == id2 && l.B == id1) {
			n++
		}
	}
	return n
}

// topologyJSON — канонический вид топологии для сравнения.
func topologyJSON(t *testing.T, topo model.Topology) string {
	t.Helper()
	data, err := json.Marshal(topo)
	if err != nil {
		t.Fatalf("JSON топологии: %v", err)
	}
	return string(data)
}

// Сценарии NR-019: фикстуры в коде, проверка узлов и связей.
var buildScenarios = []struct {
	name    string
	devices func(t *testing.T) []model.Device
	results func(t *testing.T) []snmp.TargetResult
	verify  func(t *testing.T, topo model.Topology)
}{
	{
		// (1) Два коммутатора, соединённых по LLDP с обеих сторон:
		// одна связь, а не две.
		name: "LLDP с обеих сторон — одна связь",
		devices: func(t *testing.T) []model.Device {
			return []model.Device{
				mustDev(t, "00:00:00:00:00:01", "10.0.0.1"),
				mustDev(t, "00:00:00:00:00:02", "10.0.0.2"),
				mustDev(t, "00:00:00:00:00:03", "10.0.0.30"),
			}
		},
		results: func(t *testing.T) []snmp.TargetResult {
			sw1 := target(t, "10.0.0.1", "sw-one")
			sw1.LLDP = []model.LldpNeighbor{{LocalPort: "Gi0/24", ChassisID: "00:00:00:00:00:02", RemotePort: "Gi0/24"}}
			sw2 := target(t, "10.0.0.2", "sw-two")
			sw2.LLDP = []model.LldpNeighbor{{LocalPort: "Gi0/24", ChassisID: "00:00:00:00:00:01", RemotePort: "Gi0/24"}}
			return []snmp.TargetResult{sw1, sw2}
		},
		verify: func(t *testing.T, topo model.Topology) {
			sw1 := nodeOf(t, topo, "00:00:00:00:00:01")
			if sw1.Kind != model.NodeKindSwitch || sw1.Label != "sw-one" {
				t.Errorf("узел 00:00:00:00:00:01 = %+v, хочу switch/sw-one", sw1)
			}
			sw2 := nodeOf(t, topo, "00:00:00:00:00:02")
			if sw2.Kind != model.NodeKindSwitch || sw2.Label != "sw-two" {
				t.Errorf("узел 00:00:00:00:00:02 = %+v, хочу switch/sw-two", sw2)
			}
			if n := linksBetween(topo, "00:00:00:00:00:01", "00:00:00:00:00:02"); n != 1 {
				t.Errorf("связей между коммутаторами = %d, хочу 1 (дедупликация обеих сторон)", n)
			}
			hasLink(t, topo, model.LinkSourceLLDP, "00:00:00:00:00:01", "Gi0/24", "00:00:00:00:00:02", "Gi0/24")
		},
	},
	{
		// (2) Порт без LLDP и с одним MAC — связь fdb с устройством.
		name: "порт с одним MAC — связь fdb",
		devices: func(t *testing.T) []model.Device {
			d := mustDev(t, "00:00:00:00:00:0b", "10.0.0.11")
			d.Hostname = "printer"
			return []model.Device{mustDev(t, "00:00:00:00:00:01", "10.0.0.1"), d}
		},
		results: func(t *testing.T) []snmp.TargetResult {
			sw1 := target(t, "10.0.0.1", "sw-one")
			sw1.FDB = []model.FdbEntry{{MAC: "00:00:00:00:00:0b", Port: "Gi0/1"}}
			return []snmp.TargetResult{sw1}
		},
		verify: func(t *testing.T, topo model.Topology) {
			hasLink(t, topo, model.LinkSourceFDB, "00:00:00:00:00:01", "Gi0/1", "00:00:00:00:00:0b", "")
			n := nodeOf(t, topo, "00:00:00:00:00:0b")
			if n.Kind != model.NodeKindDevice || n.Label != "printer" {
				t.Errorf("узел 00:00:00:00:00:0b = %+v, хочу device/printer", n)
			}
		},
	},
	{
		// (3) Порт без LLDP с тремя MAC — облако и три связи; MAC,
		// которых нет среди устройств, дают узлы unknown.
		name: "порт с тремя MAC — облако",
		devices: func(t *testing.T) []model.Device {
			return []model.Device{
				mustDev(t, "00:00:00:00:00:01", "10.0.0.1"),
				mustDev(t, "00:00:00:00:00:0c", "10.0.0.12"),
			}
		},
		results: func(t *testing.T) []snmp.TargetResult {
			sw1 := target(t, "10.0.0.1", "sw-one")
			sw1.FDB = []model.FdbEntry{
				{MAC: "00:00:00:00:00:0c", Port: "Gi0/2"},
				{MAC: "00:00:00:00:00:0d", Port: "Gi0/2"},
				{MAC: "00:00:00:00:00:0e", Port: "Gi0/2"},
			}
			return []snmp.TargetResult{sw1}
		},
		verify: func(t *testing.T, topo model.Topology) {
			const cloud = "cloud:00:00:00:00:00:01:Gi0/2"
			c := nodeOf(t, topo, cloud)
			if c.Kind != model.NodeKindCloud || c.Label == "" {
				t.Errorf("узел %s = %+v, хочу cloud с подписью", cloud, c)
			}
			hasLink(t, topo, model.LinkSourceInferred, "00:00:00:00:00:01", "Gi0/2", cloud, "")
			for _, mac := range []string{"00:00:00:00:00:0c", "00:00:00:00:00:0d", "00:00:00:00:00:0e"} {
				hasLink(t, topo, model.LinkSourceFDB, cloud, "", mac, "")
			}
			unknown := nodeOf(t, topo, "00:00:00:00:00:0d")
			if unknown.Kind != model.NodeKindUnknown || unknown.Label != "00:00:00:00:00:0d" {
				t.Errorf("узел 00:00:00:00:00:0d = %+v, хочу unknown с MAC в подписи", unknown)
			}
			device := nodeOf(t, topo, "00:00:00:00:00:0c")
			if device.Kind != model.NodeKindDevice {
				t.Errorf("узел 00:00:00:00:00:0c = %+v, хочу device", device)
			}
		},
	},
	{
		// (4) Транзитный порт с LLDP-соседом: MAC за ним не даёт
		// прямых связей от первого коммутатора.
		name: "транзитный порт не даёт прямых связей",
		devices: func(t *testing.T) []model.Device {
			return []model.Device{
				mustDev(t, "00:00:00:00:00:01", "10.0.0.1"),
				mustDev(t, "00:00:00:00:00:02", "10.0.0.2"),
				mustDev(t, "00:00:00:00:00:0b", "10.0.0.11"),
				mustDev(t, "00:00:00:00:00:0c", "10.0.0.12"),
			}
		},
		results: func(t *testing.T) []snmp.TargetResult {
			sw1 := target(t, "10.0.0.1", "sw-one")
			sw1.LLDP = []model.LldpNeighbor{{LocalPort: "Gi0/24", ChassisID: "00:00:00:00:00:02", RemotePort: "Gi0/24"}}
			sw1.FDB = []model.FdbEntry{
				{MAC: "00:00:00:00:00:0b", Port: "Gi0/24"}, // за sw2 — транзит
				{MAC: "00:00:00:00:00:0c", Port: "Gi0/1"},  // напрямую
			}
			sw2 := target(t, "10.0.0.2", "sw-two")
			sw2.FDB = []model.FdbEntry{{MAC: "00:00:00:00:00:0b", Port: "Gi0/1"}}
			return []snmp.TargetResult{sw1, sw2}
		},
		verify: func(t *testing.T, topo model.Topology) {
			hasLink(t, topo, model.LinkSourceLLDP, "00:00:00:00:00:01", "Gi0/24", "00:00:00:00:00:02", "Gi0/24")
			hasLink(t, topo, model.LinkSourceFDB, "00:00:00:00:00:01", "Gi0/1", "00:00:00:00:00:0c", "")
			hasLink(t, topo, model.LinkSourceFDB, "00:00:00:00:00:02", "Gi0/1", "00:00:00:00:00:0b", "")
			if n := linksBetween(topo, "00:00:00:00:00:01", "00:00:00:00:00:0b"); n != 0 {
				t.Errorf("транзитный MAC дал %d прямых связей от sw1, хочу 0 (правило транзитного порта)", n)
			}
		},
	},
	{
		// (5) Коммутатор с Error не становится узлом, его данные
		// игнорируются; остальные цели обрабатываются.
		name: "цель с ошибкой не даёт узла и связей",
		devices: func(t *testing.T) []model.Device {
			return []model.Device{
				mustDev(t, "00:00:00:00:00:01", "10.0.0.1"),
				mustDev(t, "00:00:00:00:00:0b", "10.0.0.11"),
			}
		},
		results: func(t *testing.T) []snmp.TargetResult {
			bad := target(t, "10.0.0.9", "ghost")
			bad.Error = "snmp: система: request timeout (after 2 retries)"
			bad.LLDP = []model.LldpNeighbor{{LocalPort: "Gi0/1", ChassisID: "00:00:00:00:00:0b", RemotePort: "eth0"}}
			bad.FDB = []model.FdbEntry{{MAC: "00:00:00:00:00:0b", Port: "Gi0/1"}}
			good := target(t, "10.0.0.1", "sw-one")
			good.FDB = []model.FdbEntry{{MAC: "00:00:00:00:00:0b", Port: "Gi0/1"}}
			return []snmp.TargetResult{bad, good}
		},
		verify: func(t *testing.T, topo model.Topology) {
			for _, n := range topo.Nodes {
				if n.ID == "ip:10.0.0.9" || n.Label == "ghost" {
					t.Errorf("цель с ошибкой стала узлом: %+v", n)
				}
			}
			hasLink(t, topo, model.LinkSourceFDB, "00:00:00:00:00:01", "Gi0/1", "00:00:00:00:00:0b", "")
			for _, l := range topo.Links {
				if l.A == "ip:10.0.0.9" || l.B == "ip:10.0.0.9" {
					t.Errorf("данные цели с ошибкой дали связь: %+v", l)
				}
			}
		},
	},
	{
		// (6) Мусор и пустые входы без паники: пустой граф с [].
		name: "мусор и пустые входы без паники",
		devices: func(t *testing.T) []model.Device {
			return []model.Device{
				{}, // нулевое устройство без ID — пропускается
				mustDev(t, "00:00:00:00:00:01", "10.0.0.1"),
			}
		},
		results: func(t *testing.T) []snmp.TargetResult {
			garbage := snmp.TargetResult{} // невалидная цель — пропускается
			sw1 := target(t, "10.0.0.1", "")
			sw1.LLDP = []model.LldpNeighbor{
				{LocalPort: "", ChassisID: "not-a-mac", RemotePort: ""},
				{LocalPort: "Gi0/1", ChassisID: "", RemotePort: "eth0"},
			}
			sw1.FDB = []model.FdbEntry{
				{MAC: "", Port: "Gi0/3"},
				{MAC: "ff:ff:ff:ff:ff:ff", Port: "Gi0/3"},
				{MAC: "01:00:5e:00:00:01", Port: "Gi0/3"},
				{MAC: "zz:zz", Port: "Gi0/3"},
				{MAC: "00:00:00:00:00:01", Port: "Gi0/4"}, // собственный MAC коммутатора
			}
			return []snmp.TargetResult{garbage, sw1}
		},
		verify: func(t *testing.T, topo model.Topology) {
			if topo.Nodes == nil || topo.Links == nil {
				t.Fatalf("срезы nil: %+v", topo)
			}
			for _, l := range topo.Links {
				if l.A == "00:00:00:00:00:01" && l.B == "00:00:00:00:00:01" {
					t.Errorf("собственный MAC коммутатора дал связь: %+v", l)
				}
			}
			if got := len(topo.Nodes); got != 1 {
				t.Errorf("узлов = %d, хочу 1 (только сам коммутатор): %+v", got, topo.Nodes)
			}
			if got := len(topo.Links); got != 0 {
				t.Errorf("связей = %d, хочу 0 (мусор отброшен): %+v", got, topo.Links)
			}
			node := topo.Nodes[0]
			if node.Kind != model.NodeKindSwitch || node.Label != "10.0.0.1" {
				t.Errorf("узел = %+v, хочу switch с IP в подписи (sysName пуст)", node)
			}
		},
	},
}

func TestBuildScenarios(t *testing.T) {
	for _, sc := range buildScenarios {
		sc := sc
		t.Run(sc.name, func(t *testing.T) {
			topo := Build(sc.devices(t), sc.results(t))
			sc.verify(t, topo)
			// узлы отсортированы по ID
			for i := 1; i < len(topo.Nodes); i++ {
				if topo.Nodes[i-1].ID > topo.Nodes[i].ID {
					t.Errorf("узлы не отсортированы: %q > %q", topo.Nodes[i-1].ID, topo.Nodes[i].ID)
				}
			}
			// связи отсортированы по (A, APort, B, BPort)
			for i := 1; i < len(topo.Links); i++ {
				if compareLinks(topo.Links[i-1], topo.Links[i]) > 0 {
					t.Errorf("связи не отсортированы: %+v > %+v", topo.Links[i-1], topo.Links[i])
				}
			}
		})
	}
}

// TestBuildEmptyInputs — пустые входы: пустая топология со срезами [],
// не nil.
func TestBuildEmptyInputs(t *testing.T) {
	topo := Build(nil, nil)
	if topo.Nodes == nil || topo.Links == nil {
		t.Fatalf("срезы nil: %+v", topo)
	}
	if len(topo.Nodes) != 0 || len(topo.Links) != 0 {
		t.Fatalf("хочу пустую топологию, есть: %+v", topo)
	}
	data, err := json.Marshal(topo)
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}
	const want = `{"nodes":[],"links":[]}`
	if string(data) != want {
		t.Errorf("JSON = %s, хочу %s", data, want)
	}
}

// TestBuildOrderIndependent — перемешивание входных срезов не меняет
// результат (детерминированность).
func TestBuildOrderIndependent(t *testing.T) {
	build := func(order int) string {
		devices := []model.Device{
			mustDev(t, "00:00:00:00:00:01", "10.0.0.1"),
			mustDev(t, "00:00:00:00:00:02", "10.0.0.2"),
			mustDev(t, "00:00:00:00:00:0b", "10.0.0.11"),
			mustDev(t, "00:00:00:00:00:0c", "10.0.0.12"),
			mustDev(t, "00:00:00:00:00:0d", "10.0.0.13"),
		}
		sw1 := target(t, "10.0.0.1", "sw-one")
		sw1.LLDP = []model.LldpNeighbor{{LocalPort: "Gi0/24", ChassisID: "00:00:00:00:00:02", RemotePort: "Gi0/24"}}
		sw1.FDB = []model.FdbEntry{
			{MAC: "00:00:00:00:00:0c", Port: "Gi0/1"},  // прямая связь
			{MAC: "00:00:00:00:00:0b", Port: "Gi0/24"}, // транзит за sw2
			{MAC: "00:00:00:00:00:01", Port: "Gi0/9"},  // собственный MAC
		}
		sw2 := target(t, "10.0.0.2", "sw-two")
		sw2.LLDP = []model.LldpNeighbor{{LocalPort: "Gi0/24", ChassisID: "00:00:00:00:00:01", RemotePort: "Gi0/24"}}
		sw2.FDB = []model.FdbEntry{
			{MAC: "00:00:00:00:00:0d", Port: "Gi0/1"},
		}
		results := []snmp.TargetResult{sw1, sw2}
		rng := rand.New(rand.NewSource(int64(order)))
		rng.Shuffle(len(devices), func(i, j int) { devices[i], devices[j] = devices[j], devices[i] })
		rng.Shuffle(len(results), func(i, j int) { results[i], results[j] = results[j], results[i] })
		return topologyJSON(t, Build(devices, results))
	}
	baseline := build(0)
	for order := 1; order <= 20; order++ {
		if got := build(order); got != baseline {
			t.Fatalf("порядок входа %d изменил результат:\n%s\nхочу:\n%s", order, got, baseline)
		}
	}
}
