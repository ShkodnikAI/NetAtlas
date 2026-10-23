package scanner

import (
	"net/netip"
	"sort"
	"time"

	"github.com/ShkodnikAI/NetAtlas/internal/model"
	"github.com/ShkodnikAI/NetAtlas/internal/oui"
	"github.com/ShkodnikAI/NetAtlas/scanner/dhcp"
)

// AddLeases вливает DHCP-аренды в устройства. Аренда относится к
// устройству по MAC: устройству добавляются IP (если его ещё нет),
// имя (источник «dhcp», через model.NewName — проверки имён не
// обходятся), наблюдение «dhcp» (одно на устройство, как у других
// источников) и SSID (если пуст и аренда его несёт). Аренда с IP вне
// scope игнорируется; аренда без устройства с таким MAC создаёт новое
// (класс «неизвестное») только если её IP внутри scope. Имена без
// дублей: имя не добавляется, если устройство уже носит такое же
// значение (независимо от источника). Нулевой scope — границ нет,
// все аренды игнорируются (fail-closed, как в FromARP). Результат
// отсортирован по первому IP (при равенстве — по MAC) и не зависит
// от порядка входа. Неверные аренды (некорректный MAC или IP после
// повторной проверки) пропускаются.
func AddLeases(devices []model.Device, leases []dhcp.Lease, scope *Scope, now time.Time) []model.Device {
	byMAC := make(map[string]int, len(devices))
	for i := range devices {
		byMAC[devices[i].ID] = i
	}
	for _, l := range leases {
		mac, err := model.NormalizeMAC(l.MAC) // парсер уже нормализовал; страховка
		if err != nil {
			continue
		}
		ip, err := netip.ParseAddr(l.IP)
		if err != nil {
			continue
		}
		if scope == nil || !scope.Contains(ip) {
			continue // аренда вне границ (или границ нет) игнорируется
		}
		idx, ok := byMAC[mac]
		if !ok {
			d, err := model.NewDevice(mac)
			if err != nil {
				continue
			}
			idx = len(devices)
			byMAC[mac] = idx
			devices = append(devices, d)
		}
		dev := &devices[idx]
		if !containsAddr(dev.IPs, ip) {
			dev.IPs = append(dev.IPs, ip)
		}
		if l.Hostname != "" {
			if name, err := model.NewName(model.NameSourceDHCP, l.Hostname, now); err == nil {
				if !hasNameValue(dev.Names, name.Name) {
					dev.Names = append(dev.Names, name)
				}
			}
		}
		if !hasSource(dev.Observations, "dhcp") {
			dev.Observations = append(dev.Observations, model.Observation{Source: "dhcp", Seen: now})
		}
		if dev.SSID == "" && l.SSID != "" {
			dev.SSID = l.SSID
		}
	}
	for i := range devices {
		ips := devices[i].IPs
		sort.Slice(ips, func(a, b int) bool { return ips[a].Compare(ips[b]) < 0 })
	}
	sortByFirstIP(devices)
	return devices
}

// hasNameValue сообщает, есть ли среди имён значение name независимо
// от источника: одно и то же имя не должно дублироваться в выводе.
func hasNameValue(names []model.Name, name string) bool {
	for _, n := range names {
		if n.Name == name {
			return true
		}
	}
	return false
}

// FillVendors заполняет поле Vendor у всех переданных устройств по
// встроенному реестру IEEE MA-L (internal/oui). Префикс без записи
// в реестре или локально-администрируемый MAC оставляет поле пустым.
func FillVendors(devices []model.Device) []model.Device {
	for i := range devices {
		if v, ok := oui.Lookup(devices[i].ID); ok {
			devices[i].Vendor = v
		}
	}
	return devices
}
