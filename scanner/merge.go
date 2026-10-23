package scanner

import (
	"net/netip"
	"sort"
	"time"

	"github.com/ShkodnikAI/NetAtlas/internal/model"
	"github.com/ShkodnikAI/NetAtlas/scanner/arp"
)

// FromARP превращает записи ARP-таблицы в устройства.
// Записи с IP вне scope отбрасываются (nil-Scope — границ нет:
// без проверки адрес не включается). Записи с одним MAC объединяются
// в одно устройство (IP по возрастанию, без повторов). Класс каждого
// устройства — «неизвестное», одно наблюдение с источником «arp».
// Результат отсортирован по первому IP (при равенстве — по MAC)
// и не зависит от порядка входа. Пустой вход даёт пустой срез, не nil.
func FromARP(entries []arp.Entry, scope *Scope, now time.Time) []model.Device {
	devices := make([]model.Device, 0)
	byMAC := make(map[string]int)

	for _, e := range entries {
		if scope == nil || !scope.Contains(e.IP) {
			continue
		}
		d, err := model.NewDevice(e.MAC)
		if err != nil {
			continue // парсер не выпускает такие MAC; страховка
		}
		idx, ok := byMAC[d.MAC]
		if !ok {
			idx = len(devices)
			byMAC[d.MAC] = idx
			d.Observations = append(d.Observations, model.Observation{Source: "arp", Seen: now})
			devices = append(devices, d)
		}
		dev := &devices[idx]
		if !containsAddr(dev.IPs, e.IP) {
			dev.IPs = append(dev.IPs, e.IP)
		}
	}

	for i := range devices {
		ips := devices[i].IPs
		sort.Slice(ips, func(a, b int) bool { return ips[a].Compare(ips[b]) < 0 })
	}
	sortByFirstIP(devices)
	return devices
}

// sortByFirstIP упорядочивает устройства по первому IP (при равенстве
// или отсутствии IP — по MAC). Общий порядок для FromARP и AddLeases:
// результат не зависит от порядка входа.
func sortByFirstIP(devices []model.Device) {
	sort.Slice(devices, func(a, b int) bool {
		firstA, firstB := devices[a].IPs, devices[b].IPs
		if len(firstA) == 0 || len(firstB) == 0 {
			return devices[a].MAC < devices[b].MAC
		}
		if c := firstA[0].Compare(firstB[0]); c != 0 {
			return c < 0
		}
		return devices[a].MAC < devices[b].MAC
	})
}

func containsAddr(addrs []netip.Addr, a netip.Addr) bool {
	for _, x := range addrs {
		if x == a {
			return true
		}
	}
	return false
}
