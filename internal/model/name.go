package model

import (
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

// Источники имён устройства или хоста.
const (
	NameSourceNetBIOS = "netbios"
	NameSourceMDNS    = "mdns"
	NameSourceSSDP    = "ssdp"
	NameSourceDHCP    = "dhcp"
)

// MaxNameLen — максимальная длина имени в символах.
const MaxNameLen = 255

// nameSources — множество допустимых источников имён.
var nameSources = map[string]bool{
	NameSourceNetBIOS: true,
	NameSourceMDNS:    true,
	NameSourceSSDP:    true,
	NameSourceDHCP:    true,
}

// Name — имя устройства или хоста с указанием источника и времени.
// Ответы сети — недоверенные данные, поэтому NewName ограничивает
// длину и отвергает управляющие символы.
type Name struct {
	Source string    `json:"source"`
	Name   string    `json:"name"`
	Seen   time.Time `json:"seen"`
}

// NewName создаёт имя: источник обязан быть одним из допустимых
// (netbios, mdns, ssdp); имя после обрезки по краям — непустое,
// не длиннее MaxNameLen символов и без управляющих символов.
func NewName(source, name string, seen time.Time) (Name, error) {
	if !nameSources[source] {
		return Name{}, fmt.Errorf("model: неизвестный источник имени %q", source)
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return Name{}, fmt.Errorf("model: имя пустое")
	}
	if utf8.RuneCountInString(name) > MaxNameLen {
		return Name{}, fmt.Errorf("model: имя длиннее %d символов", MaxNameLen)
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return Name{}, fmt.Errorf("model: имя содержит управляющий символ U+%04X", r)
		}
	}
	return Name{Source: source, Name: name, Seen: seen}, nil
}
