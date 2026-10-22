package names

import (
	"fmt"
	"net/netip"
	"strings"
)

// SSDPPort — порт multicast-группы SSDP.
const SSDPPort = 1900

// SSDPGroup — фиксированная multicast-группа SSDP: это адрес
// широковещательного вопроса, а не цель сканирования.
const SSDPGroup = "239.255.255.250"

// maxSSDPValue — максимальная длина значения заголовка SSDP.
const maxSSDPValue = 2048

// SSDPInfo — ответ на M-SEARCH. Location не запрашивается: хранится
// только строка заголовка.
type SSDPInfo struct {
	From     netip.Addr
	ST       string
	USN      string
	Server   string
	Location string
}

// mSearchQuery — стандартный M-SEARCH-запрос (ssdp:all).
const mSearchQuery = "M-SEARCH * HTTP/1.1\r\n" +
	"HOST: 239.255.255.250:1900\r\n" +
	"MAN: \"ssdp:discover\"\r\n" +
	"MX: 2\r\n" +
	"ST: ssdp:all\r\n" +
	"\r\n"

// MSearch возвращает байты M-SEARCH-запроса.
func MSearch() []byte {
	return []byte(mSearchQuery)
}

// ParseResponse разбирает SSDP-ответ: обязан начинаться с
// "HTTP/1.1 200"; заголовки ST, USN, SERVER, LOCATION разбираются без
// учёта регистра; значения ограничены по длине, управляющие символы
// внутри значения дают ошибку. Мусор и обрезка — ошибка без паники.
func ParseResponse(data []byte, from netip.Addr) (SSDPInfo, error) {
	text := string(data)
	if !strings.HasPrefix(text, "HTTP/1.1 200") {
		return SSDPInfo{}, fmt.Errorf("names: ssdp: ответ не начинается с HTTP/1.1 200")
	}
	lines := strings.Split(text, "\r\n")
	info := SSDPInfo{From: from}
	seen := 0
	for _, line := range lines[1:] {
		if line == "" {
			break // конец заголовков
		}
		key, value, ok := splitHeader(line)
		if !ok {
			continue // строки без двоеточия игнорируются
		}
		seen++
		switch key {
		case "ST":
			info.ST = value
		case "USN":
			info.USN = value
		case "SERVER":
			info.Server = value
		case "LOCATION":
			info.Location = value
		}
	}
	if seen == 0 {
		return SSDPInfo{}, fmt.Errorf("names: ssdp: в ответе нет заголовков")
	}
	return info, nil
}

// splitHeader разбирает строку "Key: value" без учёта регистра ключа
// и с проверкой значения (длина, отсутствие управляющих символов).
func splitHeader(line string) (string, string, bool) {
	i := strings.Index(line, ":")
	if i <= 0 {
		return "", "", false
	}
	key := strings.ToUpper(strings.TrimSpace(line[:i]))
	value := strings.TrimSpace(line[i+1:])
	if value == "" {
		return key, "", true
	}
	if len(value) > maxSSDPValue {
		return "", "", false
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return "", "", false
		}
	}
	return key, value, true
}
