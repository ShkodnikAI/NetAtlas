package model

// Виды узлов графа топологии.
const (
	// NodeKindDevice — устройство, найденное сканером (ID = MAC).
	NodeKindDevice = "device"
	// NodeKindSwitch — управляемое устройство, опрошенное по SNMP.
	NodeKindSwitch = "switch"
	// NodeKindCloud — неуправляемый коммутатор («облако») между
	// портами, за которыми видно несколько MAC-адресов.
	NodeKindCloud = "cloud"
	// Типы ручных элементов карты (NR-022): значки различаются
	// формой и подписью, тип выбирается при добавлении.
	NodeKindInternet = "internet"
	NodeKindRouter   = "router"
	NodeKindAP       = "ap"
	NodeKindServer   = "server"
	NodeKindLaptop   = "laptop"
	NodeKindPrinter  = "printer"
	// NodeKindUnknown — сосед из таблиц LLDP/FDB, которого нет среди
	// устройств сканера (ID = MAC).
	NodeKindUnknown = "unknown"
)

// Источники связей графа топологии.
const (
	// LinkSourceLLDP — соседство, увиденное по протоколу LLDP.
	LinkSourceLLDP = "lldp"
	// LinkSourceFDB — устройство за портом коммутатора по таблице MAC.
	LinkSourceFDB = "fdb"
	// LinkSourceInferred — вывод построителя: между коммутатором и
	// устройствами стоит неуправляемый коммутатор.
	LinkSourceInferred = "inferred"
)

// Node — узел графа топологии: ID (MAC устройства/соседа, ip:адрес
// коммутатора без привязки к устройству, cloud:...:порт для облака),
// вид и подпись для карты.
type Node struct {
	ID    string `json:"id"`
	Kind  string `json:"kind"`
	Label string `json:"label"`
}

// Link — связь между узлами: конец A с портом APort, конец B с
// портом BPort и источник данных. Порядок A/B выбирается по ID
// (меньший ID — конец A), чтобы результат был детерминированным.
type Link struct {
	A      string `json:"a"`
	APort  string `json:"a_port"`
	B      string `json:"b"`
	BPort  string `json:"b_port"`
	Source string `json:"source"`
}

// Topology — граф «узлы и связи». Срезы непустые (не nil), чтобы
// в JSON были [], а не null.
type Topology struct {
	Nodes []Node `json:"nodes"`
	Links []Link `json:"links"`
}

// NewTopology возвращает пустую топологию с непустыми срезами.
func NewTopology() Topology {
	return Topology{Nodes: []Node{}, Links: []Link{}}
}
