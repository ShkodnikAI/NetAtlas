package topology

import (
	"testing"

	"github.com/ShkodnikAI/NetAtlas/internal/model"
)

const (
	gwMAC = "d8:0d:17:00:00:01"
	pc1   = "02:00:00:00:00:0a"
	pc2   = "02:00:00:00:00:0b"
	gwIP  = "ip:192.168.100.1"
)

// Нет фактических связей — строится звезда к шлюзу: по связи на
// каждое устройство, шлюз сам себе связи не имеет, источник assumed.
func TestAssumedLinksStar(t *testing.T) {
	got := AssumedLinks([]string{pc1, pc2, gwMAC}, []string{gwMAC}, nil)
	want := []model.Link{
		{A: pc1, B: gwMAC, Source: model.LinkSourceAssumed},
		{A: pc2, B: gwMAC, Source: model.LinkSourceAssumed},
	}
	if len(got) != len(want) {
		t.Fatalf("AssumedLinks = %v, нужно %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("AssumedLinks[%d] = %+v, нужно %+v", i, got[i], want[i])
		}
	}
}

// Шлюз без устройства в базе (узел «ip:адрес») — звезда к нему.
func TestAssumedLinksIPGateway(t *testing.T) {
	got := AssumedLinks([]string{pc1, pc2}, []string{gwIP}, nil)
	if len(got) != 2 {
		t.Fatalf("связей %d, нужно 2: %v", len(got), got)
	}
	for _, l := range got {
		if l.A != gwIP && l.B != gwIP {
			t.Fatalf("связь не со шлюзом: %+v", l)
		}
		if l.Source != model.LinkSourceAssumed {
			t.Fatalf("источник %+v", l.Source)
		}
	}
}

// Появился хотя бы один фактический сосед (lldp/fdb/inferred) —
// предполагаемые связи не выдаются: догадка уступает данным.
func TestAssumedLinksSuppressedByRealLinks(t *testing.T) {
	for _, source := range []string{model.LinkSourceLLDP, model.LinkSourceFDB, model.LinkSourceInferred} {
		real := []model.Link{{A: pc1, B: gwMAC, Source: source}}
		if got := AssumedLinks([]string{pc1, pc2}, []string{gwMAC}, real); got != nil {
			t.Fatalf("источник %q: получены связи %v, нужно nil", source, got)
		}
	}
	// Ручные связи фактом коммутации не являются.
	manual := []model.Link{{A: pc1, B: gwMAC, Source: model.LinkSourceLLDP}}
	manual[0].Source = "manual"
	if got := AssumedLinks([]string{pc1, pc2}, []string{gwMAC}, manual); got == nil {
		t.Fatalf("ручная связь не должна подавлять звезду")
	}
}

// Ручная связь с теми же концами не дублируется предполагаемой.
func TestAssumedLinksNoDuplicateEnds(t *testing.T) {
	manual := []model.Link{{A: pc1, B: gwMAC, Source: "manual"}}
	got := AssumedLinks([]string{pc1, pc2}, []string{gwMAC}, manual)
	if len(got) != 1 {
		t.Fatalf("связей %d, нужна одна (pc2): %v", len(got), got)
	}
	l := got[0]
	if !(l.A == pc2 && l.B == gwMAC) && !(l.A == gwMAC && l.B == pc2) {
		t.Fatalf("неожиданная связь %+v", l)
	}
}

// Шлюзы и устройства без повторов и пустых ID; порядок входа не
// влияет на результат.
func TestAssumedLinksDeterministic(t *testing.T) {
	a := AssumedLinks([]string{pc2, pc1, "", gwMAC}, []string{gwMAC, gwMAC, ""}, nil)
	b := AssumedLinks([]string{pc1, pc2}, []string{gwMAC}, nil)
	if len(a) != len(b) {
		t.Fatalf("разное число связей: %d против %d", len(a), len(b))
	}
	for i := range b {
		if a[i] != b[i] {
			t.Fatalf("[%d] %+v против %+v", i, a[i], b[i])
		}
	}
}

// Нет шлюзов — предполагаемых связей нет.
func TestAssumedLinksNoGateway(t *testing.T) {
	if got := AssumedLinks([]string{pc1, pc2}, nil, nil); got != nil {
		t.Fatalf("без шлюзов получены связи: %v", got)
	}
	if got := AssumedLinks([]string{pc1}, []string{""}, nil); got != nil {
		t.Fatalf("пустой ID шлюза дал связи: %v", got)
	}
}
