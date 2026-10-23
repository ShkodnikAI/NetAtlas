package model

import (
	"fmt"
	"net/netip"
	"time"
)

// Observation — факт обнаружения устройства одним источником данных.
type Observation struct {
	Source string    `json:"source"`
	Seen   time.Time `json:"seen"`
}

// Device — устройство на карте сети. ID равен MAC-адресу.
type Device struct {
	ID           string        `json:"id"`
	MAC          string        `json:"mac"`
	IPs          []netip.Addr  `json:"ips"`
	Hostname     string        `json:"hostname,omitempty"`
	Class        Class         `json:"class"`
	Names        []Name        `json:"names"`
	Observations []Observation `json:"observations"`
	Vendor       string        `json:"vendor,omitempty"`
	SSID         string        `json:"ssid,omitempty"`
}

// NewDevice создаёт устройство по MAC-адресу: MAC нормализуется,
// ID равен нормализованному MAC, класс — «неизвестное».
// Срезы IPs, Names и Observations пустые, но не nil, чтобы в JSON были [].
func NewDevice(mac string) (Device, error) {
	m, err := NormalizeMAC(mac)
	if err != nil {
		return Device{}, fmt.Errorf("model: устройство: %w", err)
	}
	return Device{
		ID:           m,
		MAC:          m,
		IPs:          []netip.Addr{},
		Class:        ClassUnknown,
		Names:        []Name{},
		Observations: []Observation{},
	}, nil
}
