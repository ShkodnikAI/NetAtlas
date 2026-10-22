package model

import (
	"fmt"
	"net/netip"
	"time"
)

// Host — хост, обнаруженный ping-опросом, MAC которого пока неизвестен.
// Устройство (Device) идентифицируется MAC-адресом; хост — только IP.
// Связать хост с устройством сможет будущий источник с MAC
// (NetBIOS adapter status, DHCP, SNMP) — не этот наряд.
type Host struct {
	IP           netip.Addr    `json:"ip"`
	Names        []Name        `json:"names"`
	RTT          time.Duration `json:"rtt"`
	Observations []Observation `json:"observations"`
}

// NewHost создаёт хост по IPv4-адресу: срезы Names и Observations
// пустые, но не nil, чтобы в JSON были [].
func NewHost(ip netip.Addr) (Host, error) {
	if !ip.IsValid() || !ip.Is4() {
		return Host{}, fmt.Errorf("model: хост: нужен валидный IPv4-адрес, получен %v", ip)
	}
	return Host{
		IP:           ip,
		Names:        []Name{},
		Observations: []Observation{},
	}, nil
}
