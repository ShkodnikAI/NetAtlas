package names

import (
        "net/netip"
        "strings"
        "testing"
)

func TestMSearchContent(t *testing.T) {
        m := MSearch()
        s := string(m)
        for _, part := range []string{
                "M-SEARCH * HTTP/1.1\r\n",
                "HOST: 239.255.255.250:1900\r\n",
                "MAN: \"ssdp:discover\"\r\n",
                "MX: 2\r\n",
                "ST: ssdp:all\r\n",
                "\r\n",
        } {
                if !strings.Contains(s, part) {
                        t.Errorf("M-SEARCH не содержит %q", part)
                }
        }
        if !strings.HasSuffix(s, "\r\n\r\n") {
                t.Error("M-SEARCH должен заканчиваться пустой строкой")
        }
}

func TestParseSSDPResponse(t *testing.T) {
        from := netip.MustParseAddr("192.168.1.1")
        data := []byte("HTTP/1.1 200 OK\r\n" +
                "CACHE-CONTROL: max-age=1800\r\n" +
                "ST: upnp:rootdevice\r\n" +
                "USN: uuid:device-1::upnp:rootdevice\r\n" +
                "SERVER: Linux/1.0 UPnP/1.0 TestDevice/1.0\r\n" +
                "LOCATION: http://192.168.1.1:5000/desc.xml\r\n" +
                "EXT:\r\n" +
                "\r\n")
        info, err := ParseResponse(data, from)
        if err != nil {
                t.Fatalf("ParseResponse: %v", err)
        }
        if info.From != from {
                t.Errorf("From = %v, хочу %v", info.From, from)
        }
        if info.ST != "upnp:rootdevice" {
                t.Errorf("ST = %q", info.ST)
        }
        if info.USN != "uuid:device-1::upnp:rootdevice" {
                t.Errorf("USN = %q", info.USN)
        }
        if info.Server != "Linux/1.0 UPnP/1.0 TestDevice/1.0" {
                t.Errorf("Server = %q", info.Server)
        }
        if info.Location != "http://192.168.1.1:5000/desc.xml" {
                t.Errorf("Location = %q", info.Location)
        }
}

func TestParseSSDPCaseInsensitive(t *testing.T) {
        data := []byte("HTTP/1.1 200 OK\r\nst: upnp:rootdevice\r\nusn: uuid:x\r\nserver: dev\r\nlocation: http://a/\r\n\r\n")
        info, err := ParseResponse(data, netip.MustParseAddr("10.0.0.1"))
        if err != nil {
                t.Fatalf("ParseResponse: %v", err)
        }
        if info.ST != "upnp:rootdevice" || info.Server != "dev" {
                t.Errorf("заголовки в нижнем регистре не разобраны: %+v", info)
        }
}

func TestParseSSDPErrors(t *testing.T) {
        if _, err := ParseResponse([]byte("NOT-HTTP 200\r\n\r\n"), netip.Addr{}); err == nil {
                t.Error("не-HTTP вход: ожидалась ошибка")
        }
        if _, err := ParseResponse([]byte("HTTP/1.1 404 Not Found\r\n\r\n"), netip.Addr{}); err == nil {
                t.Error("404: ожидалась ошибка")
        }
        // Заголовки есть, но статус-код не 200 — префиксная проверка обязательна.
        if _, err := ParseResponse([]byte("HTTP/1.1 500 Server Error\r\nSERVER: dev\r\n\r\n"), netip.Addr{}); err == nil {
                t.Error("500 с заголовками: ожидалась ошибка")
        }
        // Не-HTTP ответ, но с заголовками — тоже отвергается.
        if _, err := ParseResponse([]byte("GARBAGE\r\nSERVER: x\r\n\r\n"), netip.Addr{}); err == nil {
                t.Error("мусор с заголовками: ожидалась ошибка")
        }
        if _, err := ParseResponse([]byte("HTTP/1.1 200 OK\r\n\r\n"), netip.Addr{}); err == nil {
                t.Error("нет заголовков: ожидалась ошибка")
        }
        // Управляющий символ в значении.
        bad := []byte("HTTP/1.1 200 OK\r\nSERVER: dev\x01ice\r\n\r\n")
        if _, err := ParseResponse(bad, netip.Addr{}); err == nil {
                t.Error("управляющий символ в значении: ожидалась ошибка")
        }
        // Слишком длинное значение.
        long := "HTTP/1.1 200 OK\r\nSERVER: " + strings.Repeat("a", 3000) + "\r\n\r\n"
        if _, err := ParseResponse([]byte(long), netip.Addr{}); err == nil {
                t.Error("значение длиннее 2048: ожидалась ошибка")
        }
}
