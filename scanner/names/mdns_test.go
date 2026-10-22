package names

import (
        "bytes"
        "encoding/binary"
        "net/netip"
        "testing"
)

func TestEncodeReverseQueryFixture(t *testing.T) {
        q, err := EncodeReverseQuery(netip.MustParseAddr("192.168.1.50"), 0x1234)
        if err != nil {
                t.Fatalf("EncodeReverseQuery: %v", err)
        }
        want := []byte{
                0x12, 0x34, // TRN ID
                0x00, 0x00, // флаги: запрос
                0x00, 0x01, // QDCOUNT
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        }
        // QNAME: 50.1.168.192.in-addr.arpa (обратный порядок октетов).
        want = append(want, 2, '5', '0', 1, '1', 3, '1', '6', '8', 3, '1', '9', '2')
        want = append(want, 7, 'i', 'n', '-', 'a', 'd', 'd', 'r')
        want = append(want, 4, 'a', 'r', 'p', 'a', 0)
        want = append(want,
                0x00, 0x0c, // QTYPE PTR
                0x80, 0x01, // QCLASS IN + QU
        )
        if !bytes.Equal(q, want) {
                t.Errorf("запрос отличается:\n получено %x\n ожидалось %x", q, want)
        }
}

func TestEncodeReverseQueryInvalid(t *testing.T) {
        if _, err := EncodeReverseQuery(netip.Addr{}, 1); err == nil {
                t.Error("невалидный адрес: ожидалась ошибка")
        }
        if _, err := EncodeReverseQuery(netip.MustParseAddr("fe80::1"), 1); err == nil {
                t.Error("IPv6: ожидалась ошибка")
        }
}

// buildMDNSResponse собирает ответ DNS с вопросом (полное имя) и одним
// PTR-ответом с компрессионным указателем на имя вопроса.
func buildMDNSResponse(id uint16) []byte {
        b := []byte{}
        b = appendUint16(b, id)
        b = appendUint16(b, 0x8400) // QR=1, AA=1
        b = appendUint16(b, 1)      // QDCOUNT
        b = appendUint16(b, 1)      // ANCOUNT
        b = appendUint16(b, 0)
        b = appendUint16(b, 0)
        // Вопрос: 50.1.168.192.in-addr.arpa, PTR, IN — имя окажется на offset 12.
        b = append(b, 2, '5', '0', 1, '1', 3, '1', '6', '8', 3, '1', '9', '2')
        b = append(b, 7, 'i', 'n', '-', 'a', 'd', 'd', 'r')
        b = append(b, 4, 'a', 'r', 'p', 'a', 0)
        b = appendUint16(b, QTypePTR)
        b = appendUint16(b, 0x0001)
        // Ответ: имя-указатель на offset 12, PTR, rdata — printer.local.
        b = append(b, 0xc0, 0x0c)
        b = appendUint16(b, QTypePTR)
        b = appendUint16(b, 0x0001)
        b = appendUint32(b, 120) // TTL
        target := []byte{7, 'p', 'r', 'i', 'n', 't', 'e', 'r', 5, 'l', 'o', 'c', 'a', 'l', 0}
        b = appendUint16(b, uint16(len(target)))
        b = append(b, target...)
        return b
}

func TestDecodeDNSResponseCompression(t *testing.T) {
        records, err := DecodeDNSResponse(buildMDNSResponse(0x1234), 0x1234)
        if err != nil {
                t.Fatalf("DecodeDNSResponse: %v", err)
        }
        if len(records) != 1 {
                t.Fatalf("записей = %d, хочу 1", len(records))
        }
        r := records[0]
        if r.Name != "50.1.168.192.in-addr.arpa" {
                t.Errorf("owner-имя = %q, хочу 50.1.168.192.in-addr.arpa", r.Name)
        }
        if r.Type != QTypePTR {
                t.Errorf("тип = %d, хочу PTR", r.Type)
        }
        if r.Target != "printer.local" {
                t.Errorf("цель = %q, хочу printer.local", r.Target)
        }
        name, ok := HostnameFromPTR(records)
        if !ok || name != "printer.local" {
                t.Errorf("HostnameFromPTR = %q, %v, хочу printer.local, true", name, ok)
        }
}

func TestDecodeDNSResponseErrors(t *testing.T) {
        if _, err := DecodeDNSResponse(buildMDNSResponse(0x7777), 0x1234); err == nil {
                t.Error("чужой TRN ID: ожидалась ошибка")
        }
        if _, err := DecodeDNSResponse([]byte{0x12, 0x34}, 0x1234); err == nil {
                t.Error("короткий пакет: ожидалась ошибка")
        }
        // Обрезка посреди указателя.
        cut := buildMDNSResponse(0x1234)[:len(buildMDNSResponse(0x1234))-10]
        if _, err := DecodeDNSResponse(cut, 0x1234); err == nil {
                t.Error("обрезанный пакет: ожидалась ошибка")
        }
}

func TestDecodeDNSResponsePointerLoop(t *testing.T) {
        // Указатель, ссылающийся сам на себя: лимит прыжков обязан сработать.
        b := []byte{}
        b = appendUint16(b, 0x1234)
        b = appendUint16(b, 0x8400)
        b = appendUint16(b, 0)
        b = appendUint16(b, 1) // ANCOUNT
        b = appendUint16(b, 0)
        b = appendUint16(b, 0)
        b = append(b, 0xc0, 0x0c) // указатель на offset 12 — на себя же
        if _, err := DecodeDNSResponse(b, 0x1234); err == nil {
                t.Error("петля указателей: ожидалась ошибка")
        }
}

func TestDecodeDNSResponseGarbageNoPanic(t *testing.T) {
        full := buildMDNSResponse(0x1234)
        for n := 0; n <= len(full); n += 5 {
                func() {
                        defer func() {
                                if r := recover(); r != nil {
                                        t.Fatalf("паника на длине %d: %v", n, r)
                                }
                        }()
                        _, _ = DecodeDNSResponse(full[:n], 0x1234)
                }()
        }
        garbage := make([]byte, 300)
        for i := range garbage {
                garbage[i] = byte(i * 91)
        }
        garbage[0], garbage[1] = 0x12, 0x34 // совпадающий TRN ID
        func() {
                defer func() {
                        if r := recover(); r != nil {
                                t.Fatalf("паника на мусоре: %v", r)
                        }
                }()
                _, _ = DecodeDNSResponse(garbage, 0x1234)
        }()
}

func TestHostnameFromPTRAbsent(t *testing.T) {
        if _, ok := HostnameFromPTR(nil); ok {
                t.Error("пустой список: ожидалось false")
        }
        // Запись не-PTR не даёт имя.
        records := []DNSRecord{{Name: "x", Type: 1, Data: []byte{1, 2, 3, 4}}}
        if _, ok := HostnameFromPTR(records); ok {
                t.Error("A-запись: ожидалось false")
        }
}

func TestUint16FieldsInResponse(t *testing.T) {
        // TTL и тип разбираются из фиксированных позиций.
        records, err := DecodeDNSResponse(buildMDNSResponse(0x1234), 0x1234)
        if err != nil {
                t.Fatalf("DecodeDNSResponse: %v", err)
        }
        if records[0].TTL != 120 {
                t.Errorf("TTL = %d, хочу 120", records[0].TTL)
        }
        if binary.BigEndian.Uint16([]byte{0x80, 0x01}) != 0x8001 {
                t.Error("константная проверка байтового порядка")
        }
}
