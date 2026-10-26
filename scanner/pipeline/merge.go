package pipeline

import (
	"net/netip"
	"sort"
	"time"

	"github.com/ShkodnikAI/NetAtlas/internal/model"
)

// mergeDevices вливает дополнительные устройства (свежая ARP-таблица
// после обхода, локальные интерфейсы — NR-030) в результат
// сканирования по MAC: IP, имена и наблюдения добавляются без дублей
// (наблюдение — одно на источник, имя — одно на значение). Хост, чей
// адрес теперь принадлежит устройству, вливается в него: наблюдения и
// имена хоста переходят устройству, сам хост из списка уходит —
// вместо «хост без MAC» появляется устройство с MAC. Результат
// детерминирован: адреса устройства по возрастанию, устройства по
// первому IP (при равенстве — по MAC), хосты по IP; порядок входа не
// влияет на итог.
func mergeDevices(devices []model.Device, hosts []model.Host, extra []model.Device, _ time.Time) ([]model.Device, []model.Host) {
	byMAC := make(map[string]int, len(devices)+len(extra))
	for i := range devices {
		byMAC[devices[i].ID] = i
	}
	for _, e := range extra {
		if e.ID == "" {
			continue // устройства без MAC не бывает; страховка
		}
		idx, ok := byMAC[e.ID]
		if !ok {
			byMAC[e.ID] = len(devices)
			devices = append(devices, e)
			continue
		}
		dev := &devices[idx]
		for _, ip := range e.IPs {
			if !containsAddr(dev.IPs, ip) {
				dev.IPs = append(dev.IPs, ip)
			}
		}
		for _, o := range e.Observations {
			if !hasObs(dev.Observations, o.Source) {
				dev.Observations = append(dev.Observations, o)
			}
		}
		for _, n := range e.Names {
			if !hasNameValue(dev.Names, n.Name) {
				dev.Names = append(dev.Names, n)
			}
		}
	}

	// Хост вливается в устройство, владеющее его адресом.
	kept := hosts[:0]
	for _, h := range hosts {
		matched := false
		for i := range devices {
			if !containsAddr(devices[i].IPs, h.IP) {
				continue
			}
			matched = true
			for _, o := range h.Observations {
				if !hasObs(devices[i].Observations, o.Source) {
					devices[i].Observations = append(devices[i].Observations, o)
				}
			}
			for _, n := range h.Names {
				if !hasNameValue(devices[i].Names, n.Name) {
					devices[i].Names = append(devices[i].Names, n)
				}
			}
			break
		}
		if !matched {
			kept = append(kept, h)
		}
	}
	hosts = kept

	// Порядок как в scanner.FromARP и scanner.AddLeases.
	for i := range devices {
		ips := devices[i].IPs
		sort.Slice(ips, func(a, b int) bool { return ips[a].Compare(ips[b]) < 0 })
	}
	sortByFirstIP(devices)
	sort.Slice(hosts, func(i, j int) bool { return hosts[i].IP.Less(hosts[j].IP) })
	return devices, hosts
}

// containsAddr — есть ли адрес в срезе.
func containsAddr(addrs []netip.Addr, a netip.Addr) bool {
	for _, x := range addrs {
		if x == a {
			return true
		}
	}
	return false
}

// hasObs — есть ли наблюдение источника source в срезе.
func hasObs(obs []model.Observation, source string) bool {
	for _, o := range obs {
		if o.Source == source {
			return true
		}
	}
	return false
}

// hasNameValue — есть ли среди имён значение name независимо от
// источника: одно и то же имя не дублируется в выводе.
func hasNameValue(names []model.Name, name string) bool {
	for _, n := range names {
		if n.Name == name {
			return true
		}
	}
	return false
}

// sortByFirstIP упорядочивает устройства по первому IP (при равенстве
// или отсутствии IP — по MAC); тот же порядок, что в scanner.
func sortByFirstIP(devices []model.Device) {
	sort.Slice(devices, func(a, b int) bool {
		if len(devices[a].IPs) == 0 || len(devices[b].IPs) == 0 {
			return devices[a].MAC < devices[b].MAC
		}
		if c := devices[a].IPs[0].Compare(devices[b].IPs[0]); c != 0 {
			return c < 0
		}
		return devices[a].MAC < devices[b].MAC
	})
}
