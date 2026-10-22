package names

import (
        "bytes"
        "encoding/binary"
        "strings"
        "testing"
)

// encHost — закодированное имя «HOST»: H=0x48→EI, O=0x4F→EP,
// S=0x53→FD, T=0x54→FE, паддинг пробелами до 15 — «CA», суффикс 0x00 — «AA».
var encHost = "EIEPFDFE" + strings.Repeat("CA", NBNameLen-4) + "AA"

// encStar — закодированное wildcard-имя «*»: 0x2A→CK, паддинг, суффикс.
var encStar = "CK" + strings.Repeat("CA", NBNameLen-1) + "AA"

func TestEncodeNetBIOSNameHost(t *testing.T) {
        enc, err := encodeNetBIOSName("host")
        if err != nil {
                t.Fatalf("encodeNetBIOSName: %v", err)
        }
        if string(enc) != encHost {
                t.Errorf("кодирование host:\n получено %q\n ожидалось %q", enc, encHost)
        }
}

func TestEncodeNetBIOSNameStar(t *testing.T) {
        enc, err := encodeNetBIOSName("*")
        if err != nil {
                t.Fatalf("encodeNetBIOSName: %v", err)
        }
        if string(enc) != encStar {
                t.Errorf("кодирование *:\n получено %q\n ожидалось %q", enc, encStar)
        }
}

func TestEncodeNetBIOSNameErrors(t *testing.T) {
        if _, err := encodeNetBIOSName("шестьнадцать_символов"); err == nil {
                t.Error("имя длиннее 15 байт: ожидалась ошибка")
        }
        if _, err := encodeNetBIOSName("a\x01b"); err == nil {
                t.Error("управляющий символ: ожидалась ошибка")
        }
}

func TestDecodeNetBIOSNameRoundTrip(t *testing.T) {
        for _, name := range []string{"host", "PC-ADMIN", "*", "A"} {
                enc, err := encodeNetBIOSName(name)
                if err != nil {
                        t.Fatalf("encodeNetBIOSName(%q): %v", name, err)
                }
                back, err := decodeNetBIOSName(enc)
                if err != nil {
                        t.Fatalf("decodeNetBIOSName(%q): %v", name, err)
                }
                // Кодирование всегда приводит к верхнему регистру (RFC 1002).
                if back != strings.ToUpper(name) {
                        t.Errorf("round-trip %q → %q", name, back)
                }
        }
}

func TestEncodeNameQueryFixture(t *testing.T) {
        q, err := EncodeNameQuery("pc-admin", 0x1234)
        if err != nil {
                t.Fatalf("EncodeNameQuery: %v", err)
        }
        want := []byte{
                0x12, 0x34, // TRN ID
                0x01, 0x00, // флаги
                0x00, 0x01, // QDCOUNT
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x20, // длина метки
        }
        enc, _ := encodeNetBIOSName("PC-ADMIN")
        want = append(want, enc...)
        want = append(want,
                0x00,       // конец имени
                0x00, 0x20, // QTYPE NB
                0x00, 0x01, // QCLASS IN
        )
        if !bytes.Equal(q, want) {
                t.Errorf("запрос отличается:\n получено %x\n ожидалось %x", q, want)
        }
}

// buildNBResponse собирает NBNS-ответ: вопрос с именем HOST, ответ —
// owner-имя указателем (ptr=true, цель — вопрос) или инлайн (encName).
func buildNBResponse(id uint16, encName []byte, ptr bool) []byte {
        encHostBytes, _ := encodeNetBIOSName("HOST")
        b := []byte{}
        b = appendUint16(b, id)
        b = appendUint16(b, 0x8000) // QR=1, RCODE=0
        b = appendUint16(b, 1)      // QDCOUNT
        b = appendUint16(b, 1)      // ANCOUNT
        b = appendUint16(b, 0)
        b = appendUint16(b, 0)
        // Вопрос (имя окажется на offset 12 — цель указателя).
        b = append(b, 0x20)
        b = append(b, encHostBytes...)
        b = append(b, 0x00)
        b = appendUint16(b, 0x0020) // QTYPE NB
        b = appendUint16(b, 0x0001) // QCLASS IN
        // Ответ.
        if ptr {
                b = append(b, 0xc0, 0x0c) // указатель на offset 12
        } else {
                b = append(b, 0x20)
                b = append(b, encName...)
                b = append(b, 0x00)
        }
        b = appendUint16(b, 0x0020) // RR TYPE NB
        b = appendUint16(b, 0x0001) // RR CLASS IN
        b = appendUint32(b, 0)      // TTL
        b = appendUint16(b, 6)      // RDLENGTH
        b = append(b, 0x00, 0x04, 192, 168, 1, 1)
        return b
}

func appendUint32(b []byte, v uint32) []byte {
        return append(b, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func TestDecodeNameResponseInline(t *testing.T) {
        // Имя с хвостовыми пробелами: трим обязателен.
        resp := buildNBResponse(0x1234, []byte(encHost), false)
        name, err := DecodeNameResponse(resp, 0x1234)
        if err != nil {
                t.Fatalf("DecodeNameResponse: %v", err)
        }
        if name != "HOST" {
                t.Errorf("имя = %q, хочу %q (пробелы обрезаны)", name, "HOST")
        }
}

func TestDecodeNameResponsePointer(t *testing.T) {
        resp := buildNBResponse(0x1234, nil, true)
        name, err := DecodeNameResponse(resp, 0x1234)
        if err != nil {
                t.Fatalf("DecodeNameResponse: %v", err)
        }
        if name != "HOST" {
                t.Errorf("имя = %q, хочу %q (через указатель)", name, "HOST")
        }
}

func TestDecodeNameResponseErrors(t *testing.T) {
        if _, err := DecodeNameResponse(buildNBResponse(0x4321, []byte(encHost), false), 0x1234); err == nil {
                t.Error("чужой TRN ID: ожидалась ошибка")
        }
        bad := buildNBResponse(0x1234, []byte(encHost), false)
        binary.BigEndian.PutUint16(bad[2:4], 0x8005) // RCODE=5
        if _, err := DecodeNameResponse(bad, 0x1234); err == nil {
                t.Error("RCODE=5: ожидалась ошибка")
        }
        notResp := buildNBResponse(0x1234, []byte(encHost), false)
        binary.BigEndian.PutUint16(notResp[2:4], 0x0100) // QR=0
        if _, err := DecodeNameResponse(notResp, 0x1234); err == nil {
                t.Error("QR=0: ожидалась ошибка")
        }
        if _, err := DecodeNameResponse([]byte{1, 2, 3}, 0x1234); err == nil {
                t.Error("короткий пакет: ожидалась ошибка")
        }
}

// buildNBStatResponse собирает NBSTAT-ответ с таблицей имён и MAC.
func buildNBStatResponse(id uint16) []byte {
        encStarBytes, _ := encodeNetBIOSName("*")
        b := []byte{}
        b = appendUint16(b, id)
        b = appendUint16(b, 0x8000)
        b = appendUint16(b, 1) // QDCOUNT
        b = appendUint16(b, 1) // ANCOUNT
        b = appendUint16(b, 0)
        b = appendUint16(b, 0)
        b = append(b, 0x20)
        b = append(b, encStarBytes...)
        b = append(b, 0x00)
        b = appendUint16(b, QTypeNBStat) // QTYPE NBSTAT
        b = appendUint16(b, 0x0001)
        // Ответ: указатель на вопрос, затем RR.
        b = append(b, 0xc0, 0x0c)
        b = appendUint16(b, QTypeNBStat) // RR TYPE
        b = appendUint16(b, 0x0001)      // RR CLASS
        b = appendUint32(b, 0)           // TTL
        rdata := []byte{}
        rdata = append(rdata, 2) // число имён
        entry := func(name string) []byte {
                raw := []byte(name)
                for len(raw) < NBNameLen {
                        raw = append(raw, 0x20)
                }
                return append(append([]byte{}, raw...), 0x00, 0x04, 0x00)
        }
        rdata = append(rdata, entry("PC-ADMIN")...)
        rdata = append(rdata, entry("WORKGROUP")...)
        rdata = append(rdata, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x01) // MAC
        b = appendUint16(b, uint16(len(rdata)))
        b = append(b, rdata...)
        return b
}

func TestDecodeNodeStatusResponse(t *testing.T) {
        names, err := DecodeNodeStatusResponse(buildNBStatResponse(0x1234), 0x1234)
        if err != nil {
                t.Fatalf("DecodeNodeStatusResponse: %v", err)
        }
        if len(names) != 2 {
                t.Fatalf("имён = %d, хочу 2", len(names))
        }
        if names[0] != "PC-ADMIN" || names[1] != "WORKGROUP" {
                t.Errorf("имена = %v, хочу [PC-ADMIN WORKGROUP] (пробелы обрезаны)", names)
        }
}

func TestDecodeNodeStatusResponseDedupAndEmpty(t *testing.T) {
        resp := buildNBStatResponse(0x1234)
        // rdata: повтор имени и пустая запись.
        // Ищем rdata: после заголовка ответа; для простоты пересобираем.
        _ = resp
        // Собираем rdata вручную: 3 записи, одна пустая, одна дубликат.
        rdata := []byte{3}
        entry := func(name string) []byte {
                raw := []byte(name)
                for len(raw) < NBNameLen {
                        raw = append(raw, 0x20)
                }
                return append(append([]byte{}, raw...), 0x00, 0x04, 0x00)
        }
        rdata = append(rdata, entry("PC-ADMIN")...)
        rdata = append(rdata, entry("")...)
        rdata = append(rdata, entry("PC-ADMIN")...)
        rdata = append(rdata, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55)

        encStarBytes, _ := encodeNetBIOSName("*")
        b := []byte{}
        b = appendUint16(b, 0x1234)
        b = appendUint16(b, 0x8000)
        b = appendUint16(b, 1) // QDCOUNT
        b = appendUint16(b, 1) // ANCOUNT
        b = appendUint16(b, 0)
        b = appendUint16(b, 0)
        b = append(b, 0x20)
        b = append(b, encStarBytes...)
        b = append(b, 0x00)
        b = appendUint16(b, QTypeNBStat)
        b = appendUint16(b, 0x0001)
        b = append(b, 0xc0, 0x0c)
        b = appendUint16(b, QTypeNBStat)
        b = appendUint16(b, 0x0001)
        b = appendUint32(b, 0)
        b = appendUint16(b, uint16(len(rdata)))
        b = append(b, rdata...)

        names, err := DecodeNodeStatusResponse(b, 0x1234)
        if err != nil {
                t.Fatalf("DecodeNodeStatusResponse: %v", err)
        }
        if len(names) != 1 || names[0] != "PC-ADMIN" {
                t.Errorf("имена = %v, хочу [PC-ADMIN] (пустое и дубликат отброшены)", names)
        }
}

func TestDecodeNodeStatusResponseErrors(t *testing.T) {
        if _, err := DecodeNodeStatusResponse(buildNBStatResponse(0x9999), 0x1234); err == nil {
                t.Error("чужой TRN ID: ожидалась ошибка")
        }
        if _, err := DecodeNodeStatusResponse([]byte{0x12}, 0x1234); err == nil {
                t.Error("короткий пакет: ожидалась ошибка")
        }
        if _, err := DecodeNodeStatusResponse(buildNBStatResponse(0x1234)[:20], 0x1234); err == nil {
                t.Error("обрезанный пакет: ожидалась ошибка")
        }
}

func TestEncodeNodeStatusQueryFixture(t *testing.T) {
        q, err := EncodeNodeStatusQuery(0xabcd)
        if err != nil {
                t.Fatalf("EncodeNodeStatusQuery: %v", err)
        }
        want := []byte{
                0xab, 0xcd,
                0x01, 0x00,
                0x00, 0x01,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x20,
        }
        want = append(want, encStar...)
        want = append(want,
                0x00,
                0x00, 0x21, // QTYPE NBSTAT
                0x00, 0x01,
        )
        if !bytes.Equal(q, want) {
                t.Errorf("запрос отличается:\n получено %x\n ожидалось %x", q, want)
        }
}

func TestNBStatGarbageNoPanic(t *testing.T) {
        // Обрезки и мусор не должны паниковать — только ошибки.
        prefix := buildNBStatResponse(0x1234)
        for n := 0; n <= len(prefix); n += 7 {
                func() {
                        defer func() {
                                if r := recover(); r != nil {
                                        t.Fatalf("паника на длине %d: %v", n, r)
                                }
                        }()
                        _, _ = DecodeNodeStatusResponse(prefix[:n], 0x1234)
                }()
        }
        garbage := make([]byte, 200)
        for i := range garbage {
                garbage[i] = byte(i * 37)
        }
        func() {
                defer func() {
                        if r := recover(); r != nil {
                                t.Fatalf("паника на мусоре: %v", r)
                        }
                }()
                _, _ = DecodeNodeStatusResponse(garbage, 0x1234)
                _, _ = DecodeNameResponse(garbage, 0x1234)
        }()
}
