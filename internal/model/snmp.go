package model

// FdbEntry — запись таблицы коммутации (FDB): MAC-адрес, наблюдаемый
// за портом коммутатора. Port — имя порта (ifName); если имя у
// ifIndex отсутствует — десятичный номер порта строкой.
type FdbEntry struct {
	MAC  string `json:"mac"`
	Port string `json:"port"`
}

// LldpNeighbor — сосед, обнаруженный по LLDP на локальном порту.
// ChassisID и RemotePort декодируются в человекочитаемый вид: MAC
// (подтип macAddress), строка (текстовые подтипы) или hex-строка
// для нечитаемых байтов. SysName — имя удалённой системы, если сосед
// его сообщил.
type LldpNeighbor struct {
	LocalPort  string `json:"local_port"`
	ChassisID  string `json:"chassis_id"`
	RemotePort string `json:"remote_port"`
	SysName    string `json:"sys_name,omitempty"`
}
