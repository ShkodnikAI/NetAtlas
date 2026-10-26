package api

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ShkodnikAI/NetAtlas/scanner"
	"github.com/ShkodnikAI/NetAtlas/scanner/arp"
	"github.com/ShkodnikAI/NetAtlas/scanner/ping"
	"github.com/ShkodnikAI/NetAtlas/scanner/pipeline"
)

// fakeScanResolver — подставной резолвер обратного DNS: считает
// запросы, всегда отвечает одним именем.
type fakeScanResolver struct {
	mu      sync.Mutex
	queries []string
}

func (r *fakeScanResolver) LookupAddr(_ context.Context, addr string) ([]string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.queries = append(r.queries, addr)
	return []string{"box.lan."}, nil
}

func (r *fakeScanResolver) asked() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.queries...)
}

// nr030Handler — API со сканом, где резолвер и локальные интерфейсы
// подставлены (герметично), а ARP даёт одно устройство 10.0.0.2.
func nr030Handler(t *testing.T, resolver *fakeScanResolver) http.Handler {
	t.Helper()
	fs := newFakeStore()
	scope, err := scanner.NewScope([]string{"10.0.0.0/24"}, false)
	if err != nil {
		t.Fatalf("scope: %v", err)
	}
	a, err := New(fs, token, scope, mustLimiter(t), &fakeProber{})
	if err != nil {
		t.Fatalf("api: %v", err)
	}
	a.ConfigureScan(ServerScanConfig{
		Subnets:   []string{"10.0.0.0/24"},
		SNMPReady: false,
	}, ScanDeps{
		ReadARP: func(ctx context.Context) ([]arp.Entry, error) {
			return []arp.Entry{{IP: netip.MustParseAddr("10.0.0.2"), MAC: "00:00:00:00:00:02"}}, nil
		},
		NewProber: func() (ping.Prober, func(), error) {
			return &fakeProber{alive: map[string]bool{"10.0.0.2": true}}, func() {}, nil
		},
		NewNameConn: func() (net.PacketConn, error) {
			return &fakeScanConn{}, nil
		},
		DNSResolver: resolver,
		ReadLocalIfaces: func() ([]pipeline.LocalIface, error) {
			return nil, nil
		},
		Hostname: func() (string, error) { return "na-test", nil },
	})
	return a.Handler()
}

// waitScanDone ждёт завершения сканирования.
func waitScanDone(t *testing.T, h http.Handler, id int64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		rec := do(h, "GET", "/api/scan/"+itoa(id), "", bearer)
		if strings.Contains(rec.Body.String(), `"done"`) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("скан не завершился: %s", rec.Body.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// Обратный DNS включён по умолчанию: резолвер опрошен для адреса
// устройства без имён.
func TestScanReverseDNSOn(t *testing.T) {
	resolver := &fakeScanResolver{}
	h := nr030Handler(t, resolver)
	rec := do(h, "POST", "/api/scan", `{"subnets":["10.0.0.0/24"],"ping":true,"confirm":true}`, bearer)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("запуск: код %d: %s", rec.Code, rec.Body.String())
	}
	waitScanDone(t, h, scanID(t, rec.Body.String()))
	asked := resolver.asked()
	if len(asked) != 1 || asked[0] != "10.0.0.2" {
		t.Fatalf("запросы резолвера: %v, хочу [10.0.0.2]", asked)
	}
}

// no_dns=true — ни одного запроса к резолверу.
func TestScanNoDNSFlag(t *testing.T) {
	resolver := &fakeScanResolver{}
	h := nr030Handler(t, resolver)
	rec := do(h, "POST", "/api/scan", `{"subnets":["10.0.0.0/24"],"ping":true,"confirm":true,"no_dns":true}`, bearer)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("запуск: код %d: %s", rec.Code, rec.Body.String())
	}
	waitScanDone(t, h, scanID(t, rec.Body.String()))
	if got := resolver.asked(); len(got) != 0 {
		t.Fatalf("запросы при no_dns: %v, хочу пусто", got)
	}
}
