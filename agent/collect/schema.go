// Схема отчёта инвентаря, версия 1 (NR-006). Все скалярные поля —
// строки: сценарии отдают строки (локаль-независимо), парсеры
// нормализуют только там, где нужно. Отсутствующие поля опускаются
// (omitempty), а не заполняются нулями.
package collect

// SchemaVersion — версия схемы отчёта; идёт в каждом отправлении.
const SchemaVersion = 1

// Report — полный отчёт инвентаря (payload отправления).
type Report struct {
	InventorySchemaVersion int          `json:"inventory_schema_version"`
	CollectedAt            string       `json:"collected_at"`
	Hostname               string       `json:"hostname"`
	OS                     *OSInfo      `json:"os,omitempty"`
	Hardware               *Hardware    `json:"hardware,omitempty"`
	Disks                  *Disks       `json:"disks,omitempty"`
	Network                []NetAdapter `json:"network,omitempty"`
	Drivers                []Driver     `json:"drivers,omitempty"`
	Programs               []Program    `json:"programs,omitempty"`
	CollectorErrors        []string     `json:"collector_errors,omitempty"`
}

// OSInfo — операционная система и обновления.
type OSInfo struct {
	Caption        string   `json:"caption,omitempty"`
	Version        string   `json:"version,omitempty"`
	BuildNumber    string   `json:"build_number,omitempty"`
	Architecture   string   `json:"architecture,omitempty"`
	LastBootUpTime string   `json:"last_boot_up_time,omitempty"`
	Hotfixes       []Hotfix `json:"hotfixes,omitempty"`
	LatestHotfix   string   `json:"latest_hotfix,omitempty"` // дата последнего обновления (строкой, как отдала локаль)
}

// Hotfix — установленное обновление.
type Hotfix struct {
	ID          string `json:"id,omitempty"`
	Description string `json:"description,omitempty"`
	InstalledOn string `json:"installed_on,omitempty"`
}

// Hardware — процессор, ОЗУ, плата, BIOS.
type Hardware struct {
	TotalPhysicalMemory string         `json:"total_physical_memory,omitempty"` // байты, строкой
	CPUs                []CPU          `json:"cpus,omitempty"`
	MemoryModules       []MemoryModule `json:"memory_modules,omitempty"`
	BaseBoard           *Board         `json:"base_board,omitempty"`
	BIOS                *BIOS          `json:"bios,omitempty"`
}

// CPU — физический процессор.
type CPU struct {
	Name        string `json:"name,omitempty"`
	Cores       int    `json:"cores,omitempty"`
	Logical     int    `json:"logical,omitempty"`
	MaxClockMHz int    `json:"max_clock_mhz,omitempty"`
}

// MemoryModule — модуль ОЗУ (слот, объём, частота).
type MemoryModule struct {
	Slot         string `json:"slot,omitempty"`
	Bank         string `json:"bank,omitempty"`
	Capacity     string `json:"capacity,omitempty"` // байты, строкой
	SpeedMHz     int    `json:"speed_mhz,omitempty"`
	Manufacturer string `json:"manufacturer,omitempty"`
}

// Board — материнская плата.
type Board struct {
	Manufacturer string `json:"manufacturer,omitempty"`
	Product      string `json:"product,omitempty"`
}

// BIOS — версия BIOS/UEFI.
type BIOS struct {
	Manufacturer string `json:"manufacturer,omitempty"`
	Version      string `json:"version,omitempty"`
	ReleaseDate  string `json:"release_date,omitempty"` // ГГГГ-ММ-ДД или как отдала система
}

// Disks — физические диски и тома.
type Disks struct {
	Disks   []Disk   `json:"disks,omitempty"`
	Volumes []Volume `json:"volumes,omitempty"`
}

// Disk — физический диск; износ и температура — если диск их
// отдаёт, иначе поля отсутствуют (не нули).
type Disk struct {
	FriendlyName string `json:"friendly_name,omitempty"`
	SerialNumber string `json:"serial,omitempty"`
	MediaType    string `json:"media_type,omitempty"`
	BusType      string `json:"bus_type,omitempty"`
	Size         string `json:"size,omitempty"`
	Health       string `json:"health,omitempty"`
	Wear         *int   `json:"wear,omitempty"`        // процент износа SSD
	Temperature  *int   `json:"temperature,omitempty"` // °C
}

// Volume — логический том.
type Volume struct {
	DriveLetter   string `json:"drive_letter,omitempty"`
	Label         string `json:"label,omitempty"`
	FileSystem    string `json:"file_system,omitempty"`
	DriveType     string `json:"drive_type,omitempty"`
	Size          string `json:"size,omitempty"`
	SizeRemaining string `json:"size_remaining,omitempty"`
}

// NetAdapter — сетевой адаптер.
type NetAdapter struct {
	Name        string   `json:"name,omitempty"`
	Description string   `json:"description,omitempty"`
	MAC         string   `json:"mac,omitempty"`
	LinkSpeed   string   `json:"link_speed,omitempty"`
	Status      string   `json:"status,omitempty"`
	IPv4        []string `json:"ipv4,omitempty"`
}

// Driver — подписанный драйвер устройства.
type Driver struct {
	DeviceName   string `json:"device_name,omitempty"`
	Manufacturer string `json:"manufacturer,omitempty"`
	Version      string `json:"version,omitempty"`
	Date         string `json:"date,omitempty"` // ГГГГ-ММ-ДД
}

// Program — установленная программа (ключи Uninstall реестра).
type Program struct {
	Name        string `json:"name,omitempty"`
	Version     string `json:"version,omitempty"`
	Publisher   string `json:"publisher,omitempty"`
	InstallDate string `json:"install_date,omitempty"` // ГГГГММДД как в реестре
}
