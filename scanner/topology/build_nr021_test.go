package topology

import (
	"math/rand"
	"testing"

	"github.com/ShkodnikAI/NetAtlas/internal/model"
	"github.com/ShkodnikAI/NetAtlas/scanner/snmp"
)

// Сценарии NR-021: точность топологии без LLDP.

// (1) Два коммутатора без LLDP, нижний с тремя компьютерами: верхний
// не рисует облако на uplink-порту, компьютеры привязаны к нижнему
// коммутатору, между коммутаторами одна связь inferred.
func TestNR021NearestPort(t *testing.T) {
	devices := []model.Device{
		mustDev(t, "00:00:00:00:00:01", "10.0.0.1"),
		mustDev(t, "00:00:00:00:00:02", "10.0.0.2"),
		mustDev(t, "00:00:00:00:00:0b", "10.0.0.11"),
		mustDev(t, "00:00:00:00:00:0c", "10.0.0.12"),
		mustDev(t, "00:00:00:00:00:0d", "10.0.0.13"),
	}
	sw1 := target(t, "10.0.0.1", "sw-up")
	sw1.FDB = []model.FdbEntry{
		{MAC: "00:00:00:00:00:0b", Port: "Gi0/24"},
		{MAC: "00:00:00:00:00:0c", Port: "Gi0/24"},
		{MAC: "00:00:00:00:00:0d", Port: "Gi0/24"},
	}
	sw2 := target(t, "10.0.0.2", "sw-down")
	sw2.FDB = []model.FdbEntry{
		{MAC: "00:00:00:00:00:0b", Port: "Gi0/1"},
		{MAC: "00:00:00:00:00:0c", Port: "Gi0/2"},
		{MAC: "00:00:00:00:00:0d", Port: "Gi0/3"},
	}
	topo := Build(devices, []snmp.TargetResult{sw1, sw2})

	for _, n := range topo.Nodes {
		if n.Kind == model.NodeKindCloud {
			t.Errorf("лишнее облако без LLDP: %+v", n)
		}
	}
	hasLink(t, topo, model.LinkSourceFDB, "00:00:00:00:00:02", "Gi0/1", "00:00:00:00:00:0b", "")
	hasLink(t, topo, model.LinkSourceFDB, "00:00:00:00:00:02", "Gi0/2", "00:00:00:00:00:0c", "")
	hasLink(t, topo, model.LinkSourceFDB, "00:00:00:00:00:02", "Gi0/3", "00:00:00:00:00:0d", "")
	for _, mac := range []string{"00:00:00:00:00:0b", "00:00:00:00:00:0c", "00:00:00:00:00:0d"} {
		if n := linksBetween(topo, "00:00:00:00:00:01", mac); n != 0 {
			t.Errorf("верхний коммутатор связан с %s: %d связей, хочу 0 (MAC за соседом)", mac, n)
		}
	}
	if n := linksBetween(topo, "00:00:00:00:00:01", "00:00:00:00:00:02"); n != 1 {
		t.Errorf("связей между коммутаторами = %d, хочу 1 (inferred)", n)
	}
	hasLink(t, topo, model.LinkSourceInferred, "00:00:00:00:00:01", "Gi0/24", "00:00:00:00:00:02", "")
}

// (2) Настоящий неуправляемый коммутатор: три компьютера на одном
// порту, второго FDB нет — облако остаётся.
func TestNR021CloudStays(t *testing.T) {
	devices := []model.Device{
		mustDev(t, "00:00:00:00:00:01", "10.0.0.1"),
		mustDev(t, "00:00:00:00:00:0b", "10.0.0.11"),
	}
	sw1 := target(t, "10.0.0.1", "sw-one")
	sw1.FDB = []model.FdbEntry{
		{MAC: "00:00:00:00:00:0b", Port: "Gi0/2"},
		{MAC: "00:00:00:00:00:0c", Port: "Gi0/2"},
		{MAC: "00:00:00:00:00:0d", Port: "Gi0/2"},
	}
	topo := Build(devices, []snmp.TargetResult{sw1})

	const cloud = "cloud:00:00:00:00:00:01:Gi0/2"
	c := nodeOf(t, topo, cloud)
	if c.Kind != model.NodeKindCloud || c.Label == "" {
		t.Fatalf("узел %s = %+v, хочу cloud с подписью", cloud, c)
	}
	hasLink(t, topo, model.LinkSourceInferred, "00:00:00:00:00:01", "Gi0/2", cloud, "")
	for _, mac := range []string{"00:00:00:00:00:0b", "00:00:00:00:00:0c", "00:00:00:00:00:0d"} {
		hasLink(t, topo, model.LinkSourceFDB, cloud, "", mac, "")
	}
}

// (3) MAC коммутатора с большим IP не влияет на порт верхнего
// коммутатора: предсбор MAC коммутаторов делает результат одинаковым
// при любом порядке целей.
func TestNR021SwitchMACKnownBeforeFDB(t *testing.T) {
	devices := []model.Device{
		mustDev(t, "00:00:00:00:00:01", "10.0.0.1"),
		mustDev(t, "00:00:00:00:00:02", "10.0.0.2"),
		mustDev(t, "00:00:00:00:00:0b", "10.0.0.11"),
	}
	build := func(shuffleSeed int64) model.Topology {
		sw1 := target(t, "10.0.0.1", "sw-up")
		sw1.FDB = []model.FdbEntry{
			{MAC: "00:00:00:00:00:02", Port: "Gi0/24"}, // MAC нижнего коммутатора
			{MAC: "00:00:00:00:00:0b", Port: "Gi0/24"}, // компьютер за ним
		}
		sw2 := target(t, "10.0.0.2", "sw-down")
		results := []snmp.TargetResult{sw1, sw2}
		if shuffleSeed > 0 {
			rng := rand.New(rand.NewSource(shuffleSeed))
			rng.Shuffle(len(devices), func(i, j int) { devices[i], devices[j] = devices[j], devices[i] })
			rng.Shuffle(len(results), func(i, j int) { results[i], results[j] = results[j], results[i] })
		}
		return Build(devices, results)
	}
	topo := build(0)

	if n := linksBetween(topo, "00:00:00:00:00:01", "cloud:00:00:00:00:00:01:Gi0/24"); n != 0 {
		t.Errorf("MAC коммутатора с большим IP дал облако на порту верхнего: %+v", topo.Links)
	}
	for _, n := range topo.Nodes {
		if n.ID == "00:00:00:00:00:02" && n.Kind != model.NodeKindSwitch {
			t.Errorf("узел нижнего коммутатора = %+v, хочу switch", n)
		}
	}
	hasLink(t, topo, model.LinkSourceFDB, "00:00:00:00:00:01", "Gi0/24", "00:00:00:00:00:0b", "")

	baseline := topologyJSON(t, topo)
	for seed := int64(1); seed <= 20; seed++ {
		if got := topologyJSON(t, build(seed)); got != baseline {
			t.Fatalf("порядок входа %d изменил результат:\n%s\nхочу:\n%s", seed, got, baseline)
		}
	}
}

// (4) Сценарий (1) при перемешивании входных срезов даёт тот же граф.
func TestNR021OrderIndependent(t *testing.T) {
	build := func(order int) string {
		devices := []model.Device{
			mustDev(t, "00:00:00:00:00:01", "10.0.0.1"),
			mustDev(t, "00:00:00:00:00:02", "10.0.0.2"),
			mustDev(t, "00:00:00:00:00:0b", "10.0.0.11"),
			mustDev(t, "00:00:00:00:00:0c", "10.0.0.12"),
			mustDev(t, "00:00:00:00:00:0d", "10.0.0.13"),
		}
		sw1 := target(t, "10.0.0.1", "sw-up")
		sw1.FDB = []model.FdbEntry{
			{MAC: "00:00:00:00:00:0b", Port: "Gi0/24"},
			{MAC: "00:00:00:00:00:0c", Port: "Gi0/24"},
			{MAC: "00:00:00:00:00:0d", Port: "Gi0/24"},
		}
		sw2 := target(t, "10.0.0.2", "sw-down")
		sw2.FDB = []model.FdbEntry{
			{MAC: "00:00:00:00:00:0b", Port: "Gi0/1"},
			{MAC: "00:00:00:00:00:0c", Port: "Gi0/2"},
			{MAC: "00:00:00:00:00:0d", Port: "Gi0/3"},
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

// (5) LLDP-связь между коммутаторами не дублируется inferred-связью:
// uplink-порт с LLDP-соседом транзитный, чужие MAC за соседом.
func TestNR021NoInferredDupOfLLDP(t *testing.T) {
	devices := []model.Device{
		mustDev(t, "00:00:00:00:00:01", "10.0.0.1"),
		mustDev(t, "00:00:00:00:00:02", "10.0.0.2"),
		mustDev(t, "00:00:00:00:00:0b", "10.0.0.11"),
	}
	sw1 := target(t, "10.0.0.1", "sw-one")
	sw1.LLDP = []model.LldpNeighbor{{LocalPort: "Gi0/24", ChassisID: "00:00:00:00:00:02", RemotePort: "Gi0/24"}}
	sw1.FDB = []model.FdbEntry{
		{MAC: "00:00:00:00:00:0b", Port: "Gi0/24"}, // за LLDP-соседом
		{MAC: "00:00:00:00:00:0c", Port: "Gi0/1"},  // ближе здесь
	}
	sw2 := target(t, "10.0.0.2", "sw-two")
	sw2.FDB = []model.FdbEntry{
		{MAC: "00:00:00:00:00:0b", Port: "Gi0/1"},
		{MAC: "00:00:00:00:00:0c", Port: "Gi0/2"}, // у sw2 порт с одним чужим MAC
	}
	topo := Build(devices, []snmp.TargetResult{sw1, sw2})

	if n := linksBetween(topo, "00:00:00:00:00:01", "00:00:00:00:00:02"); n != 1 {
		t.Errorf("связей между коммутаторами = %d, хочу 1 (только LLDP, без дубля inferred)", n)
	}
	for _, l := range topo.Links {
		if l.Source == model.LinkSourceInferred {
			t.Errorf("лишняя inferred-связь при живом LLDP: %+v", l)
		}
	}
	hasLink(t, topo, model.LinkSourceFDB, "00:00:00:00:00:01", "Gi0/1", "00:00:00:00:00:0c", "")
	hasLink(t, topo, model.LinkSourceFDB, "00:00:00:00:00:02", "Gi0/1", "00:00:00:00:00:0b", "")
}
