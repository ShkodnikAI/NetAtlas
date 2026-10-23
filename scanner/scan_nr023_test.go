// Тесты NR-023 в сканере: ответы SSDP от гостей и «известных без
// агента» не сохраняются как имена; присутствие не трогается.

package scanner

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/ShkodnikAI/NetAtlas/internal/model"
	"github.com/ShkodnikAI/NetAtlas/scanner/arp"
	"github.com/ShkodnikAI/NetAtlas/scanner/names"
)

// SSDP отвечает двум устройствам; адрес гостя в SkipSSDPForIPs — имя
// из его ответа отбрасывается, у обычного устройства имя остаётся.
func TestSSDPSkippedForGuestIPs(t *testing.T) {
	scope, _ := NewScope([]string{"192.168.1.0/29"}, false)
	limiter, _ := NewLimiter(4, 10000, nil)
	now := time.Now()

	entries := []arp.Entry{
		{IP: netip.MustParseAddr("192.168.1.2"), MAC: "02:00:00:00:00:02"},
		{IP: netip.MustParseAddr("192.168.1.3"), MAC: "02:00:00:00:00:03"},
	}

	conn := &scanFakeConn{inbox: make(chan scanReadItem, 64)}
	client := names.NewClient(conn)
	client.NBTimeout = 10 * time.Millisecond
	client.MDNSTimeout = 10 * time.Millisecond
	client.SSDPWindow = 30 * time.Millisecond

	wrote := false
	conn.onWrite = func(data []byte, addr net.Addr) {
		udp, ok := addr.(*net.UDPAddr)
		if !ok || udp.Port != names.SSDPPort || wrote {
			return
		}
		wrote = true
		resp := []byte("HTTP/1.1 200 OK\r\nSERVER: Dev/1.0\r\n\r\n")
		for _, raw := range []string{"192.168.1.2", "192.168.1.3"} {
			a := netip.MustParseAddr(raw).As4()
			conn.inbox <- scanReadItem{data: resp, addr: &net.UDPAddr{IP: net.IP(a[:]), Port: 1900}}
		}
	}

	opt := Options{
		Names:          true,
		Now:            now,
		NameClient:     client,
		SkipSSDPForIPs: map[string]bool{"192.168.1.2": true},
	}
	res, err := Run(context.Background(), entries, scope, limiter, opt)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	byMAC := map[string][]model.Name{}
	for _, d := range res.Devices {
		byMAC[d.ID] = d.Names
	}
	// Гость: устройство в результате (присутствие сохранено), но без
	// SSDP-имени.
	guest, ok := byMAC["02:00:00:00:00:02"]
	if !ok {
		t.Fatalf("устройство-гость пропало из результата")
	}
	if len(guest) != 0 {
		t.Fatalf("у гостя имена %+v, хочу пусто (ответ SSDP не сохраняется)", guest)
	}
	normal, ok := byMAC["02:00:00:00:00:03"]
	if !ok {
		t.Fatalf("обычное устройство пропало из результата")
	}
	if len(normal) != 1 || normal[0].Source != model.NameSourceSSDP || normal[0].Name != "Dev/1.0" {
		t.Fatalf("у обычного устройства имена %+v, хочу [ssdp Dev/1.0]", normal)
	}
}
