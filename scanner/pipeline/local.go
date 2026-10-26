package pipeline

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"time"

	"github.com/ShkodnikAI/NetAtlas/internal/model"
	"github.com/ShkodnikAI/NetAtlas/scanner"
)

// LocalIface — локальный сетевой интерфейс этой машины: имя, MAC
// (строкой, как его даёт net.HardwareAddr) и IPv4-адреса.
type LocalIface struct {
	Name  string
	MAC   string
	Addrs []netip.Addr
}

// readLocalIfaces — настоящая реализация источника «локальные
// интерфейсы» (NR-030): только активные (FlagUp) не-loopback
// интерфейсы этой машины с их IPv4-адресами.
func readLocalIfaces() ([]LocalIface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("pipeline: локальные интерфейсы: %w", err)
	}
	out := make([]LocalIface, 0, len(ifaces))
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue // спящие и loopback интерфейсы не участвуют
		}
		li := LocalIface{Name: ifc.Name}
		if ifc.HardwareAddr != nil {
			li.MAC = ifc.HardwareAddr.String()
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue // интерфейс без адресов не мешает остальным
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip, ok := netip.AddrFromSlice(ipn.IP)
			if !ok {
				continue
			}
			ip = ip.Unmap()
			if !ip.Is4() {
				continue // устройству нужен IPv4
			}
			li.Addrs = append(li.Addrs, ip)
		}
		out = append(out, li)
	}
	return out, nil
}

// localDevices собирает устройство этой машины (NR-030): MAC
// интерфейса, IPv4-адреса внутри границ сканирования, наблюдение
// «local» и имя машины (os.Hostname, источник «local»). Интерфейсы
// без MAC и без адресов внутри границ устройство не создают;
// несколько интерфейсов с одним MAC дают одно устройство (слияние по
// MAC в mergeDevices). nil-Scope никого не пропускает (fail closed).
func localDevices(scope *scanner.Scope, deps Deps, now time.Time) ([]model.Device, error) {
	read := deps.ReadLocalIfaces
	if read == nil {
		read = readLocalIfaces
	}
	ifaces, err := read()
	if err != nil {
		return nil, fmt.Errorf("pipeline: локальные интерфейсы: %w", err)
	}
	hostname := ""
	if deps.Hostname != nil {
		if name, err := deps.Hostname(); err == nil {
			hostname = name
		}
	} else if name, err := os.Hostname(); err == nil {
		hostname = name
	}
	devices := make([]model.Device, 0)
	for _, li := range ifaces {
		mac, err := model.NormalizeMAC(li.MAC)
		if err != nil {
			continue // интерфейс без MAC устройства не создаёт
		}
		d, err := model.NewDevice(mac)
		if err != nil {
			continue // NormalizeMAC уже прошёл; страховка
		}
		for _, a := range li.Addrs {
			if scope != nil && scope.Contains(a) && !containsAddr(d.IPs, a) {
				d.IPs = append(d.IPs, a)
			}
		}
		if len(d.IPs) == 0 {
			continue // адресов внутри границ нет — устройство не нужно
		}
		d.Observations = append(d.Observations, model.Observation{Source: "local", Seen: now})
		if hostname != "" {
			if n, err := model.NewName(model.NameSourceLocal, hostname, now); err == nil {
				d.Names = append(d.Names, n)
			}
		}
		devices = append(devices, d)
	}
	return devices, nil
}
