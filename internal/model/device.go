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
	Observations []Observation `json:"observations"`
}

// NewDevice создаёт устройство по MAC-адресу: MAC нормализуется,
// ID равен нормализованному MAC, класс — «неизвестное».
// Срезы IPs и Observations пустые, но не nil, чтобы в JSON были [].
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
		Observations: []Observation{},
	}, nil
}
