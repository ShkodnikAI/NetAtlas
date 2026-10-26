package devkind

import (
	"testing"

	"github.com/ShkodnikAI/NetAtlas/internal/model"
)

// Таблица правил NR-032 п.1: производители из наряда и пограничные
// случаи конфликта свидетельств.
func TestClassify(t *testing.T) {
	cases := []struct {
		name string
		in   Input
		want string
	}{
		// Принтеры по производителю (наряд: Canon, HP, Epson, Brother,
		// Kyocera, Xerox, Ricoh).
		{"Canon", Input{Vendor: "Canon", MAC: "00:80:77:00:00:01"}, model.NodeKindPrinter},
		{"HP", Input{Vendor: "HP Inc.", MAC: "00:80:77:00:00:02"}, model.NodeKindPrinter},
		{"Hewlett", Input{Vendor: "Hewlett-Packard", MAC: "00:80:77:00:00:03"}, model.NodeKindPrinter},
		{"Epson", Input{Vendor: "Seiko Epson", MAC: "00:80:77:00:00:04"}, model.NodeKindPrinter},
		{"Brother", Input{Vendor: "Brother Industries", MAC: "00:80:77:00:00:05"}, model.NodeKindPrinter},
		{"Kyocera", Input{Vendor: "Kyocera Document Solutions", MAC: "00:80:77:00:00:06"}, model.NodeKindPrinter},
		{"Xerox", Input{Vendor: "Xerox Corp", MAC: "00:80:77:00:00:07"}, model.NodeKindPrinter},
		{"Ricoh", Input{Vendor: "Ricoh Company", MAC: "00:80:77:00:00:08"}, model.NodeKindPrinter},
		// Принтер по имени из NetBIOS/mDNS, даже без производителя.
		{"имя printer", Input{Hostname: "", Names: []string{"printer-hp-1 этаж"}, MAC: "00:00:5e:00:00:01"}, model.NodeKindPrinter},
		{"имя мфу", Input{Hostname: "мфу-канцелярия", MAC: "00:00:5e:00:00:02"}, model.NodeKindPrinter},

		// Роутеры: Huawei/TP-Link/MikroTik/Keenetic/Zyxel/ZTE/D-Link
		// при совпадении с адресом шлюза (п.1, п.2).
		{"Huawei шлюз", Input{Vendor: "Huawei Technologies", IsGateway: true, MAC: "d8:0d:17:00:00:01"}, model.NodeKindRouter},
		{"TP-Link шлюз", Input{Vendor: "TP-Link Systems", IsGateway: true, MAC: "d8:0d:17:00:00:02"}, model.NodeKindRouter},
		{"MikroTik шлюз", Input{Vendor: "MikroTik", IsGateway: true, MAC: "d8:0d:17:00:00:03"}, model.NodeKindRouter},
		{"Keenetic шлюз", Input{Vendor: "Keenetic Ltd", IsGateway: true, MAC: "d8:0d:17:00:00:04"}, model.NodeKindRouter},
		{"Zyxel шлюз", Input{Vendor: "Zyxel", IsGateway: true, MAC: "d8:0d:17:00:00:05"}, model.NodeKindRouter},
		{"ZTE шлюз", Input{Vendor: "ZTE Corp", IsGateway: true, MAC: "d8:0d:17:00:00:06"}, model.NodeKindRouter},
		{"D-Link шлюз", Input{Vendor: "D-Link Corp", IsGateway: true, MAC: "d8:0d:17:00:00:07"}, model.NodeKindRouter},
		// Шлюз без известного производителя — всё равно роутер: факт
		// маршрутизации сильнее отсутствия OUI.
		{"шлюз без OUI", Input{IsGateway: true, MAC: "00:00:5e:00:00:09"}, model.NodeKindRouter},

		// Телефоны: Apple/Samsung/Xiaomi, случайный MAC (наряд:
		// b2:be:…, имя Android.local).
		{"случайный MAC Android.local", Input{Names: []string{"Android.local"}, MAC: "b2:be:ad:1f:22:33"}, model.NodeKindPhone},
		{"случайный MAC без имени", Input{MAC: "b2:be:ad:1f:22:44"}, model.NodeKindPhone},
		{"Apple без имени ПК", Input{Vendor: "Apple, Inc.", MAC: "f0:18:98:00:00:01"}, model.NodeKindPhone},
		{"Samsung", Input{Vendor: "Samsung Electronics", MAC: "f0:18:98:00:00:02"}, model.NodeKindPhone},
		{"Xiaomi", Input{Vendor: "Xiaomi Communications", MAC: "f0:18:98:00:00:03"}, model.NodeKindPhone},
		{"iphone по имени", Input{Names: []string{"iphone-anna"}, MAC: "00:00:5e:00:00:0a"}, model.NodeKindPhone},

		// IoT: Espressif, Shenzhen iComm, Tuya (наряд: модуль Shenzhen
		// iComm).
		{"Espressif", Input{Vendor: "Espressif Inc.", MAC: "24:6f:28:00:00:01"}, model.NodeKindIot},
		{"Shenzhen iComm", Input{Vendor: "Shenzhen iComm Semiconductor", MAC: "24:6f:28:00:00:02"}, model.NodeKindIot},
		{"Tuya", Input{Vendor: "Tuya Smart", MAC: "24:6f:28:00:00:03"}, model.NodeKindIot},
		{"esp32 по имени", Input{Hostname: "esp32-датчик-кухня", MAC: "00:00:5e:00:00:0b"}, model.NodeKindIot},

		// Сервер по имени: системный блок SERVAK из фактов наряда.
		{"SERVAK", Input{Hostname: "SERVAK", Vendor: "Giga-Byte", MAC: "00:00:5e:00:00:0c"}, model.NodeKindServer},
		{"nas", Input{Hostname: "nas-server", MAC: "00:00:5e:00:00:0d"}, model.NodeKindServer},

		// Телевизор по имени.
		{"tv", Input{Hostname: "living-room-tv", MAC: "00:00:5e:00:00:0e"}, model.NodeKindTV},
		{"телевизор", Input{Names: []string{"телевизор-кухня"}, MAC: "00:00:5e:00:00:0f"}, model.NodeKindTV},

		// Ноутбук и точка доступа.
		{"ThinkPad", Input{Hostname: "thinkpad-x1", MAC: "00:00:5e:00:00:10"}, model.NodeKindLaptop},
		{"точка доступа", Input{Hostname: "ap-office-2", MAC: "00:00:5e:00:00:11"}, model.NodeKindAP},

		// Компьютеры: имя ПК отменяет «телефон по случайному MAC»
		// (наряд: системные блоки Giga-Byte, SALby — остаются device).
		{"Giga-Byte без свидетелей", Input{Vendor: "Giga-Byte Technology", MAC: "00:00:5e:00:00:12"}, model.NodeKindDevice},
		{"SALby", Input{Vendor: "SALby", MAC: "00:00:5e:00:00:13"}, model.NodeKindDevice},
		{"случайный MAC с именем ПК", Input{Hostname: "office-pc-01", MAC: "b2:be:ad:1f:22:55"}, model.NodeKindDevice},
		{"пустой вход", Input{}, model.NodeKindDevice},

		// Порты печати, если они уже известны вызывающему.
		{"порт 9100", Input{Ports: []int{80, 9100}, MAC: "00:00:5e:00:00:14"}, model.NodeKindPrinter},

		// Конфликт: шлюз сvendorом принтера — роутер (шлюз сильнее).
		{"шлюз-«Canon»", Input{Vendor: "Canon", IsGateway: true, MAC: "00:80:77:00:00:15"}, model.NodeKindRouter},
		// Конфликт: сервер со случайным MAC — сервер (имя сильнее MAC).
		{"SERVAK со случайным MAC", Input{Hostname: "SERVAK", MAC: "b2:be:ad:1f:22:66"}, model.NodeKindServer},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Classify(tc.in); got != tc.want {
				t.Fatalf("Classify(%+v) = %q, нужно %q", tc.in, got, tc.want)
			}
		})
	}
}

// randomMAC распознаёт бит U/L в первом октете; некорректный MAC —
// не случайный.
func TestRandomMAC(t *testing.T) {
	cases := []struct {
		mac  string
		want bool
	}{
		{"b2:be:ad:1f:22:33", true},  // бит U/L выставлен
		{"b6:be:ad:1f:22:33", true},  // и с чётным/нечётным вторым битом
		{"02:00:00:00:00:0a", true},  // фикстуры NR-031 тоже случайные
		{"00:00:5e:00:00:01", false}, // валидный OUI
		{"d8:0d:17:00:00:01", false}, // Huawei
		{"ff:ff:ff:ff:ff:ff", false}, // групповой — ошибка нормализации
		{"мусор", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := randomMAC(tc.mac); got != tc.want {
			t.Fatalf("randomMAC(%q) = %v, нужно %v", tc.mac, got, tc.want)
		}
	}
}
