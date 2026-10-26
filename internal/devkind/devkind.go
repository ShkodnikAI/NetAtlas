// Package devkind — классификатор типов устройств по метаданным
// (NR-032 п.1). Сеть пакет не трогает: Classify — чистая функция,
// вход только читается. Источники признаков: производитель (OUI),
// hostname и имена (mDNS, NetBIOS, SSDP), признак случайно
// администрируемого MAC (бит U/L в первом октете — телефоны и
// планшеты), принадлежность адресу шлюза по умолчанию и открытые
// порты, если они уже известны вызывающему.
//
// Результат — kind из набора графа: router, printer, server, laptop,
// device, ap и новые phone, iot, tv. Вывод хранится как kind_auto;
// ручной тип владельца перекрывает его на уровне хранилища.
//
// Правила собраны в таблицу rules и применяются по порядку: первый
// совпавший rule определяет тип. Порядок задаёт силу свидетельства
// и разрешает конфликт неоднозначного вывода (NR-032 п.1): ручной
// тип владельца сильнее всего (учитывается не здесь, а в хранилище),
// затем шлюз, затем остальные правила — от конкретного
// производителя к общему признаку случайного MAC.
package devkind

import (
	"strings"

	"github.com/ShkodnikAI/NetAtlas/internal/model"
)

// Input — метаданные одного устройства для классификации.
type Input struct {
	// Vendor — производитель из OUI-таблицы (может быть пустым).
	Vendor string
	// Hostname — имя хоста (может быть пустым).
	Hostname string
	// Names — имена из mDNS, NetBIOS и SSDP.
	Names []string
	// MAC — нормализованный MAC-адрес (ID устройства).
	MAC string
	// IsGateway — адрес устройства совпадает с адресом шлюза по
	// умолчанию, известным серверу (NR-032 п.2).
	IsGateway bool
	// Ports — открытые порты, если они уже известны вызывающему
	// (сейчас источник данных отсутствует, поле задел на будущее).
	Ports []int
}

// rule — одно правило таблицы: свидетельство (совпадение) и тип.
type rule struct {
	kind  string
	match func(in Input) bool
}

// подстроки-свидетельства. Регистр не учитывается: имена приходят из
// сети в произвольном регистре.
var (
	printerVendors = []string{"canon", "hp", "hewlett", "epson", "brother", "kyocera", "xerox", "ricoh"}
	printerNames   = []string{"printer", "print", "мфу", "prn"}
	routerVendors  = []string{"huawei", "tp-link", "mikrotik", "keenetic", "zyxel", "zte", "d-link", "asustek", "netgear"}
	phoneVendors   = []string{"apple", "samsung", "xiaomi", "honor", "oppo", "realme"}
	phoneNames     = []string{"android", "iphone", "pixel", "redmi", "galaxy"}
	// имена ПК: отменяют «телефон по случайному MAC» (office-pc-01 —
	// не телефон, даже если MAC сгенерирован системой).
	pcNames = []string{"pc", "desktop", "workstation"}
	// отдельные маркеры ноутбука: на них правило laptop, а не phone.
	laptopNames   = []string{"notebook", "laptop", "thinkpad", "macbook"}
	serverNames   = []string{"server", "servak", "nas", "srv"}
	tvNames       = []string{"tv", "телевизор"}
	iotVendors    = []string{"espressif", "shenzhen icomm", "tuya"}
	iotNames      = []string{"esp-", "esp32", "esp8266", "tasmota", "sonoff", "yeelight", "shelly"}
	laptopVendors = []string{"lenovo", "dell inc", "acer"}
	apNames       = []string{"ap-", "access-point", "точка доступа"}
)

// hasSub — есть ли в s подстрока sub без учёта регистра.
func hasSub(s, sub string) bool {
	return strings.Contains(strings.ToLower(s), sub)
}

// hasAnySub — хоть одна подстрока из списка встречается в s.
func hasAnySub(s string, subs []string) bool {
	for _, sub := range subs {
		if hasSub(s, sub) {
			return true
		}
	}
	return false
}

// randomMAC — первый октет MAC имеет бит U/L (0x02): адрес не от
// производителя, а сгенерирован устройством. Типичный признак
// телефонов и планшетов в Wi-Fi-сетях.
func randomMAC(mac string) bool {
	b, err := model.NormalizeMAC(mac)
	if err != nil {
		return false
	}
	first, ok := parseFirstByte(b)
	return ok && first&0x02 != 0
}

// parseFirstByte — первый октет нормализованного MAC «aa:bb:…».
func parseFirstByte(mac string) (byte, bool) {
	if len(mac) < 2 {
		return 0, false
	}
	hi := hexNibble(mac[0])
	lo := hexNibble(mac[1])
	if hi < 0 || lo < 0 {
		return 0, false
	}
	return byte(hi)<<4 | byte(lo), true
}

func hexNibble(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	}
	return -1
}

// nameOf — hostname и имена устройства одной строкой (для поиска
// свидетельств по подстрокам).
func nameOf(in Input) string {
	parts := make([]string, 0, len(in.Names)+1)
	if in.Hostname != "" {
		parts = append(parts, in.Hostname)
	}
	parts = append(parts, in.Names...)
	return strings.Join(parts, " ")
}

// vendorOf — производитель строчными буквами: свидетельства по
// подстрокам ищутся в нормализованном виде.
func vendorOf(in Input) string {
	return strings.ToLower(in.Vendor)
}

// portIs — есть ли среди известных портов порт p.
func portIs(ports []int, p int) bool {
	for _, v := range ports {
		if v == p {
			return true
		}
	}
	return false
}

// rules — таблица правил по силе свидетельства. Порядок разрешает
// конфликт: шлюз сильнее производителя (Huawei-принтер на адресе
// шлюза — роутер), конкретное имя сильнее общего признака (SERVAK со
// случайным MAC — сервер, а не телефон).
var rules = []rule{
	// Шлюз по умолчанию: сеть устроена звездой, узел сверху (п.2).
	{"router", func(in Input) bool { return in.IsGateway }},
	// Порты печати — самые надёжные свидетельства принтера.
	{"printer", func(in Input) bool { return portIs(in.Ports, 9100) || portIs(in.Ports, 631) }},
	// Производители печатной техники.
	{"printer", func(in Input) bool { return hasAnySub(vendorOf(in), printerVendors) }},
	// Имена печати: printer-hp, мфу-канцелярия, prn-2.
	{"printer", func(in Input) bool { return hasAnySub(nameOf(in), printerNames) }},
	// Серверы и хранилища по имени: SERVAK, nas-server, srv-1.
	{"server", func(in Input) bool { return hasAnySub(nameOf(in), serverNames) }},
	// Телевизоры по имени: living-room-tv, телевизор-кухня.
	{"tv", func(in Input) bool { return hasAnySub(nameOf(in), tvNames) }},
	// Производители IoT-модулей: Espressif, Shenzhen iComm, Tuya.
	{"iot", func(in Input) bool { return hasAnySub(vendorOf(in), iotVendors) }},
	// Имена IoT-платформ: esp32-датчик, sonoff-реле.
	{"iot", func(in Input) bool { return hasAnySub(nameOf(in), iotNames) }},
	// Точка доступа по имени, если производитель не сказал своего.
	{"ap", func(in Input) bool { return hasAnySub(nameOf(in), apNames) }},
	// Телефоны по имени: Android.local, iphone-anna.
	{"phone", func(in Input) bool { return hasAnySub(nameOf(in), phoneNames) }},
	// Телефоны по производителю без имени ПК: Apple/Samsung/Xiaomi.
	{"phone", func(in Input) bool {
		return hasAnySub(vendorOf(in), phoneVendors) && !hasAnySub(nameOf(in), pcNames)
	}},
	// Случайный MAC сам по себе не делает устройство телефоном: так же
	// выглядят виртуальные машины, контейнеры и ретрансляторы (NR-032,
	// уточнение аудитора). Без имени или производителя телефона — unknown.
	{"unknown", func(in Input) bool {
		return randomMAC(in.MAC) && !hasAnySub(nameOf(in), pcNames)
	}},
	// Ноутбуки по производителю и имени (notebook, thinkpad,
	// macbook); «pc/desktop» — маркер настольной машины, он выше
	// отменил только «телефон».
	{"laptop", func(in Input) bool { return hasAnySub(vendorOf(in), laptopVendors) }},
	{"laptop", func(in Input) bool { return hasAnySub(nameOf(in), laptopNames) }},
	// Роутеры по производителю без адреса шлюза: вероятно роутер,
	// но без факта маршрутизации остаётся предположением того же
	// уровня, что остальные правила (после более сильных свидетелей).
	{"router", func(in Input) bool { return hasAnySub(vendorOf(in), routerVendors) }},
}

// Classify выводит тип устройства по метаданным. Ни одно правило не
// сработало — device (компьютер/прочее): это базовый тип узла графа.
func Classify(in Input) string {
	for _, r := range rules {
		if r.match(in) {
			return r.kind
		}
	}
	return model.NodeKindDevice
}
