// Сборщики (NR-006): интерфейс Collector, шесть сборщиков тем,
// парсеры вывода PowerShell в схему. Каждый сборщик independent:
// ошибка одного не роняет отчёт.
package collect

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Collector — один сборщик темы.
type Collector interface {
	Name() string
	Collect(ctx context.Context) (json.RawMessage, error)
}

// Имена сборщиков (ключ в collector_errors и маппинг в отчёт).
const (
	NameOS       = "osinfo"
	NameHardware = "hardware"
	NameDisks    = "disks"
	NameNetwork  = "network"
	NameDrivers  = "drivers"
	NamePrograms = "programs"
)

// DefaultCollectors — набор сборщиков по наряду.
func DefaultCollectors(run ScriptRunner) []Collector {
	return []Collector{
		&scriptCollector{run: run, name: NameOS, script: "osinfo", parse: parseOSInfo},
		&scriptCollector{run: run, name: NameHardware, script: "hardware", parse: parseHardware},
		&scriptCollector{run: run, name: NameDisks, script: "disks", parse: parseDisks},
		&scriptCollector{run: run, name: NameNetwork, script: "network", parse: parseNetwork},
		&scriptCollector{run: run, name: NameDrivers, script: "drivers", parse: parseDrivers},
		&scriptCollector{run: run, name: NamePrograms, script: "programs", parse: parsePrograms},
	}
}

// scriptCollector — общий каркас: имя встроенного сценария +
// парсер его вывода.
type scriptCollector struct {
	run    ScriptRunner
	name   string
	script string
	parse  func(json.RawMessage) (any, error)
}

func (c *scriptCollector) Name() string { return c.name }

func (c *scriptCollector) Collect(ctx context.Context) (json.RawMessage, error) {
	raw, err := c.run.Run(ctx, c.script)
	if err != nil {
		return nil, err
	}
	if _, err := c.parse(raw); err != nil {
		return nil, fmt.Errorf("разбор вывода: %w", err)
	}
	return raw, nil
}

// BuildReport — полный отчёт: версия схемы, время, хост, результаты
// всех сборщиков; ошибки — в CollectorErrors, не наверх.
func BuildReport(ctx context.Context, hostname string, cs []Collector, now time.Time) Report {
	rep := Report{
		InventorySchemaVersion: SchemaVersion,
		CollectedAt:            now.UTC().Format(time.RFC3339),
		Hostname:               hostname,
	}
	for _, c := range cs {
		raw, err := c.Collect(ctx)
		switch {
		case err != nil:
			rep.CollectorErrors = append(rep.CollectorErrors, c.Name()+": "+err.Error())
		default:
			if aerr := rep.absorb(c.Name(), raw); aerr != nil {
				rep.CollectorErrors = append(rep.CollectorErrors, c.Name()+": "+aerr.Error())
			}
		}
	}
	return rep
}

// absorb кладёт вывод сборщика в поле отчёта.
func (r *Report) absorb(name string, raw json.RawMessage) error {
	switch name {
	case NameOS:
		v, err := parseOSInfo(raw)
		if err != nil {
			return err
		}
		r.OS = v.(*OSInfo)
	case NameHardware:
		v, err := parseHardware(raw)
		if err != nil {
			return err
		}
		r.Hardware = v.(*Hardware)
	case NameDisks:
		v, err := parseDisks(raw)
		if err != nil {
			return err
		}
		r.Disks = v.(*Disks)
	case NameNetwork:
		v, err := parseNetwork(raw)
		if err != nil {
			return err
		}
		r.Network = v.([]NetAdapter)
	case NameDrivers:
		v, err := parseDrivers(raw)
		if err != nil {
			return err
		}
		r.Drivers = v.([]Driver)
	case NamePrograms:
		v, err := parsePrograms(raw)
		if err != nil {
			return err
		}
		r.Programs = v.([]Program)
	default:
		return fmt.Errorf("неизвестный сборщик %q", name)
	}
	return nil
}

// --- парсеры (покрыты фикстурами testdata, включая русскую локаль) ---

func parseOSInfo(raw json.RawMessage) (any, error) {
	var src struct {
		Caption        json.RawMessage `json:"caption"`
		Version        json.RawMessage `json:"version"`
		BuildNumber    json.RawMessage `json:"buildNumber"`
		Architecture   json.RawMessage `json:"architecture"`
		LastBootUpTime json.RawMessage `json:"lastBootUpTime"`
		Hotfixes       json.RawMessage `json:"hotfixes"`
	}
	if err := json.Unmarshal(raw, &src); err != nil {
		return nil, err
	}
	out := &OSInfo{
		Caption:        asString(src.Caption),
		Version:        asString(src.Version),
		BuildNumber:    asString(src.BuildNumber),
		Architecture:   asString(src.Architecture),
		LastBootUpTime: asString(src.LastBootUpTime),
	}
	items, err := arrayFrom(src.Hotfixes)
	if err != nil {
		return nil, err
	}
	// Последнее обновление: сценарий отдаёт список, отсортированный
	// по InstalledOn, — берём последний непустой. Локальные форматы
	// дат в Go не сравниваются.
	var latest string
	for _, it := range items {
		var h struct {
			ID          json.RawMessage `json:"id"`
			Description json.RawMessage `json:"description"`
			InstalledOn json.RawMessage `json:"installedOn"`
		}
		if err := json.Unmarshal(it, &h); err != nil {
			return nil, err
		}
		hf := Hotfix{ID: asString(h.ID), Description: asString(h.Description), InstalledOn: asString(h.InstalledOn)}
		out.Hotfixes = append(out.Hotfixes, hf)
		if hf.InstalledOn != "" {
			latest = hf.InstalledOn
		}
	}
	out.LatestHotfix = latest
	return out, nil
}

func parseHardware(raw json.RawMessage) (any, error) {
	var src struct {
		TotalPhysicalMemory json.RawMessage `json:"totalPhysicalMemory"`
		CPUs                json.RawMessage `json:"cpus"`
		MemoryModules       json.RawMessage `json:"memoryModules"`
		BaseBoard           json.RawMessage `json:"baseBoard"`
		BIOS                json.RawMessage `json:"bios"`
	}
	if err := json.Unmarshal(raw, &src); err != nil {
		return nil, err
	}
	out := &Hardware{TotalPhysicalMemory: asString(src.TotalPhysicalMemory)}
	items, err := arrayFrom(src.CPUs)
	if err != nil {
		return nil, err
	}
	for _, it := range items {
		var c struct {
			Name        json.RawMessage `json:"name"`
			Cores       json.RawMessage `json:"cores"`
			Logical     json.RawMessage `json:"logical"`
			MaxClockMHz json.RawMessage `json:"maxClockMHz"`
		}
		if err := json.Unmarshal(it, &c); err != nil {
			return nil, err
		}
		out.CPUs = append(out.CPUs, CPU{
			Name:        asString(c.Name),
			Cores:       asInt(c.Cores),
			Logical:     asInt(c.Logical),
			MaxClockMHz: asInt(c.MaxClockMHz),
		})
	}
	items, err = arrayFrom(src.MemoryModules)
	if err != nil {
		return nil, err
	}
	for _, it := range items {
		var m struct {
			Slot         json.RawMessage `json:"slot"`
			Bank         json.RawMessage `json:"bank"`
			Capacity     json.RawMessage `json:"capacity"`
			SpeedMHz     json.RawMessage `json:"speedMHz"`
			Manufacturer json.RawMessage `json:"manufacturer"`
		}
		if err := json.Unmarshal(it, &m); err != nil {
			return nil, err
		}
		out.MemoryModules = append(out.MemoryModules, MemoryModule{
			Slot:         asString(m.Slot),
			Bank:         asString(m.Bank),
			Capacity:     asString(m.Capacity),
			SpeedMHz:     asInt(m.SpeedMHz),
			Manufacturer: asString(m.Manufacturer),
		})
	}
	if len(src.BaseBoard) > 0 && string(src.BaseBoard) != "null" {
		var b struct {
			Manufacturer json.RawMessage `json:"manufacturer"`
			Product      json.RawMessage `json:"product"`
		}
		if err := json.Unmarshal(src.BaseBoard, &b); err != nil {
			return nil, err
		}
		out.BaseBoard = &Board{Manufacturer: asString(b.Manufacturer), Product: asString(b.Product)}
	}
	if len(src.BIOS) > 0 && string(src.BIOS) != "null" {
		var b struct {
			Manufacturer json.RawMessage `json:"manufacturer"`
			Version      json.RawMessage `json:"version"`
			ReleaseDate  json.RawMessage `json:"releaseDate"`
		}
		if err := json.Unmarshal(src.BIOS, &b); err != nil {
			return nil, err
		}
		out.BIOS = &BIOS{
			Manufacturer: asString(b.Manufacturer),
			Version:      asString(b.Version),
			ReleaseDate:  normalizeCIMDate(asString(b.ReleaseDate)),
		}
	}
	return out, nil
}

func parseDisks(raw json.RawMessage) (any, error) {
	var src struct {
		Disks   json.RawMessage `json:"disks"`
		Volumes json.RawMessage `json:"volumes"`
	}
	if err := json.Unmarshal(raw, &src); err != nil {
		return nil, err
	}
	out := &Disks{}
	items, err := arrayFrom(src.Disks)
	if err != nil {
		return nil, err
	}
	for _, it := range items {
		var d struct {
			FriendlyName json.RawMessage `json:"friendlyName"`
			Serial       json.RawMessage `json:"serial"`
			MediaType    json.RawMessage `json:"mediaType"`
			BusType      json.RawMessage `json:"busType"`
			Size         json.RawMessage `json:"size"`
			Health       json.RawMessage `json:"health"`
			Wear         json.RawMessage `json:"wear"`
			Temperature  json.RawMessage `json:"temperature"`
		}
		if err := json.Unmarshal(it, &d); err != nil {
			return nil, err
		}
		disk := Disk{
			FriendlyName: asString(d.FriendlyName),
			SerialNumber: asString(d.Serial),
			MediaType:    asString(d.MediaType),
			BusType:      asString(d.BusType),
			Size:         asString(d.Size),
			Health:       asString(d.Health),
		}
		// Износ и температура: отсутствуют, а не нули, если диск их
		// не отдал (HDD или нет прав на счётчики).
		if v, ok := asOptInt(d.Wear); ok {
			disk.Wear = &v
		}
		if v, ok := asOptInt(d.Temperature); ok {
			disk.Temperature = &v
		}
		out.Disks = append(out.Disks, disk)
	}
	items, err = arrayFrom(src.Volumes)
	if err != nil {
		return nil, err
	}
	for _, it := range items {
		var v struct {
			DriveLetter   json.RawMessage `json:"driveLetter"`
			Label         json.RawMessage `json:"label"`
			FileSystem    json.RawMessage `json:"fileSystem"`
			DriveType     json.RawMessage `json:"driveType"`
			Size          json.RawMessage `json:"size"`
			SizeRemaining json.RawMessage `json:"sizeRemaining"`
		}
		if err := json.Unmarshal(it, &v); err != nil {
			return nil, err
		}
		out.Volumes = append(out.Volumes, Volume{
			DriveLetter:   asString(v.DriveLetter),
			Label:         asString(v.Label),
			FileSystem:    asString(v.FileSystem),
			DriveType:     asString(v.DriveType),
			Size:          asString(v.Size),
			SizeRemaining: asString(v.SizeRemaining),
		})
	}
	return out, nil
}

func parseNetwork(raw json.RawMessage) (any, error) {
	var src struct {
		Adapters json.RawMessage `json:"adapters"`
	}
	if err := json.Unmarshal(raw, &src); err != nil {
		return nil, err
	}
	items, err := arrayFrom(src.Adapters)
	if err != nil {
		return nil, err
	}
	out := []NetAdapter{}
	for _, it := range items {
		var a struct {
			Name        json.RawMessage `json:"name"`
			Description json.RawMessage `json:"description"`
			MAC         json.RawMessage `json:"mac"`
			LinkSpeed   json.RawMessage `json:"linkSpeed"`
			Status      json.RawMessage `json:"status"`
			IPv4        json.RawMessage `json:"ipv4"`
		}
		if err := json.Unmarshal(it, &a); err != nil {
			return nil, err
		}
		na := NetAdapter{
			Name:        asString(a.Name),
			Description: asString(a.Description),
			MAC:         asString(a.MAC),
			LinkSpeed:   asString(a.LinkSpeed),
			Status:      asString(a.Status),
			IPv4:        []string{},
		}
		ips, err := arrayFrom(a.IPv4)
		if err != nil {
			return nil, err
		}
		for _, ip := range ips {
			if s := asString(ip); s != "" {
				na.IPv4 = append(na.IPv4, s)
			}
		}
		out = append(out, na)
	}
	return out, nil
}

func parseDrivers(raw json.RawMessage) (any, error) {
	var src struct {
		Drivers json.RawMessage `json:"drivers"`
	}
	if err := json.Unmarshal(raw, &src); err != nil {
		return nil, err
	}
	items, err := arrayFrom(src.Drivers)
	if err != nil {
		return nil, err
	}
	out := []Driver{}
	for _, it := range items {
		var d struct {
			DeviceName    json.RawMessage `json:"deviceName"`
			Manufacturer  json.RawMessage `json:"manufacturer"`
			DriverVersion json.RawMessage `json:"driverVersion"`
			DriverDate    json.RawMessage `json:"driverDate"`
		}
		if err := json.Unmarshal(it, &d); err != nil {
			return nil, err
		}
		name := asString(d.DeviceName)
		if name == "" {
			continue // записи без устройства нет в отчёте
		}
		out = append(out, Driver{
			DeviceName:   name,
			Manufacturer: asString(d.Manufacturer),
			Version:      asString(d.DriverVersion),
			Date:         normalizeCIMDate(asString(d.DriverDate)),
		})
	}
	return out, nil
}

func parsePrograms(raw json.RawMessage) (any, error) {
	var src struct {
		Programs json.RawMessage `json:"programs"`
	}
	if err := json.Unmarshal(raw, &src); err != nil {
		return nil, err
	}
	items, err := arrayFrom(src.Programs)
	if err != nil {
		return nil, err
	}
	out := []Program{}
	for _, it := range items {
		var p struct {
			Name        json.RawMessage `json:"name"`
			Version     json.RawMessage `json:"version"`
			Publisher   json.RawMessage `json:"publisher"`
			InstallDate json.RawMessage `json:"installDate"`
		}
		if err := json.Unmarshal(it, &p); err != nil {
			return nil, err
		}
		name := asString(p.Name)
		if name == "" {
			continue
		}
		out = append(out, Program{
			Name:        name,
			Version:     asString(p.Version),
			Publisher:   asString(p.Publisher),
			InstallDate: asString(p.InstallDate),
		})
	}
	return out, nil
}

// asInt — строка с целым (включая локальные хвосты) → int; не число — 0.
func asInt(raw json.RawMessage) int {
	s := asString(raw)
	if s == "" {
		return 0
	}
	if n, err := strconv.Atoi(s); err == nil {
		return n
	}
	return 0
}

// asOptInt — целое или null; second=false — поле отсутствует.
func asOptInt(raw json.RawMessage) (int, bool) {
	if len(raw) == 0 {
		return 0, false
	}
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "null" || trimmed == "" {
		return 0, false
	}
	n := asInt(raw)
	return n, true
}

// normalizeCIMDate — CIM-дата WMI «20240101000000.000000+180» →
// «2024-01-01»; прочие форматы (строка локали) остаются как есть.
func normalizeCIMDate(s string) string {
	if len(s) >= 8 {
		isDigits := true
		for i := 0; i < 8; i++ {
			if s[i] < '0' || s[i] > '9' {
				isDigits = false
				break
			}
		}
		if isDigits {
			return s[:4] + "-" + s[4:6] + "-" + s[6:8]
		}
	}
	return s
}
