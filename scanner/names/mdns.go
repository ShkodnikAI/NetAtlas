package names

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strings"
)

// QTypePTR — тип записи PTR (обратный запрос имени).
const QTypePTR = 12

// maxLabelJumps — предел переходов по компрессионным указателям
// (защита от петель в недоверенных данных).
const maxLabelJumps = 8

// DNSRecord — запись из ответа DNS/mDNS.
type DNSRecord struct {
	Name   string // owner-имя записи
	Type   uint16
	Class  uint16
	TTL    uint32
	Data   []byte // сырой rdata
	Target string // для PTR: декодированное имя цели (rdata — тоже имя)
}

// EncodeReverseQuery собирает mDNS-обратный запрос (QU: ответ
// ожидается юникастом) для IPv4-адреса: имя d.c.b.a.in-addr.arpa,
// QTYPE PTR, QCLASS IN с верхним битом (unicast reply).
func EncodeReverseQuery(ip netip.Addr, trnID uint16) ([]byte, error) {
	if !ip.IsValid() || !ip.Is4() {
		return nil, fmt.Errorf("names: mdns: нужен валидный IPv4-адрес, получен %v", ip)
	}
	b4 := ip.As4()
	b := make([]byte, 0, 12+16+4)
	b = appendUint16(b, trnID)
	b = appendUint16(b, 0x0000) // флаги: запрос
	b = appendUint16(b, 1)      // QDCOUNT
	b = appendUint16(b, 0)      // ANCOUNT
	b = appendUint16(b, 0)      // NSCOUNT
	b = appendUint16(b, 0)      // ARCOUNT
	// QNAME: четыре октета адреса, затем in-addr.arpa.
	for i := 3; i >= 0; i-- {
		b = append(b, byte(len(netFormatUint(b4[i]))))
		b = append(b, netFormatUint(b4[i])...)
	}
	b = append(b, 7)
	b = append(b, "in-addr"...)
	b = append(b, 4)
	b = append(b, "arpa"...)
	b = append(b, 0)
	b = appendUint16(b, QTypePTR)      // QTYPE PTR
	b = appendUint16(b, 0x8000|0x0001) // QCLASS IN + QU (unicast reply)
	return b, nil
}

func netFormatUint(v byte) string {
	// Десятичная запись октета без ведущих нулей.
	if v == 0 {
		return "0"
	}
	var buf [3]byte
	n := 0
	for v > 0 {
		buf[n] = byte('0' + v%10)
		v /= 10
		n++
	}
	out := make([]byte, n)
	for i := 0; i < n; i++ {
		out[i] = buf[n-1-i]
	}
	return string(out)
}

// DecodeDNSResponse разбирает ответ DNS/mDNS: TRN ID обязан совпадать,
// вопросы пропускаются, ответы разбираются (компрессионные указатели
// обрабатываются, петли отсекаются лимитом прыжков). Для PTR-записей
// Target содержит декодированное имя цели.
func DecodeDNSResponse(data []byte, trnID uint16) ([]DNSRecord, error) {
	if len(data) < 12 {
		return nil, fmt.Errorf("names: короткий DNS-ответ: %d байт", len(data))
	}
	if id := binary.BigEndian.Uint16(data[0:2]); id != trnID {
		return nil, fmt.Errorf("names: чужой TRN ID: %#04x, хочу %#04x", id, trnID)
	}
	qd := int(binary.BigEndian.Uint16(data[4:6]))
	an := int(binary.BigEndian.Uint16(data[6:8]))

	off := 12
	for i := 0; i < qd; i++ {
		var err error
		if off, err = skipDNSName(data, off); err != nil {
			return nil, err
		}
		if off+4 > len(data) {
			return nil, fmt.Errorf("names: вопрос DNS обрезан")
		}
		off += 4 // QTYPE + QCLASS
	}

	records := make([]DNSRecord, 0, an)
	for i := 0; i < an; i++ {
		name, next, err := readDNSName(data, off)
		if err != nil {
			return nil, err
		}
		off = next
		if off+10 > len(data) {
			return nil, fmt.Errorf("names: ответ DNS обрезан")
		}
		rec := DNSRecord{
			Name:  name,
			Type:  binary.BigEndian.Uint16(data[off : off+2]),
			Class: binary.BigEndian.Uint16(data[off+2 : off+4]),
			TTL:   binary.BigEndian.Uint32(data[off+4 : off+8]),
		}
		rdlen := int(binary.BigEndian.Uint16(data[off+8 : off+10]))
		off += 10
		if off+rdlen > len(data) {
			return nil, fmt.Errorf("names: rdata выходит за границы пакета")
		}
		rec.Data = append([]byte(nil), data[off:off+rdlen]...)
		if rec.Type == QTypePTR {
			target, _, err := readDNSName(data, off)
			if err != nil {
				return nil, fmt.Errorf("names: PTR rdata: %w", err)
			}
			rec.Target = target
		}
		off += rdlen
		records = append(records, rec)
	}
	return records, nil
}

// HostnameFromPTR возвращает имя хоста из первой PTR-записи:
// хвостовая точка снимается; пустое имя — false.
func HostnameFromPTR(records []DNSRecord) (string, bool) {
	for _, r := range records {
		if r.Type != QTypePTR || r.Target == "" {
			continue
		}
		name := strings.TrimSuffix(r.Target, ".")
		if name == "" {
			continue
		}
		return name, true
	}
	return "", false
}

// readDNSName читает имя в проводном формате DNS с позиции off,
// обрабатывая компрессионные указатели (0xC0): прыжки ограничены
// maxLabelJumps, выход за границы пакета и управляющие символы — ошибка.
func readDNSName(data []byte, off int) (string, int, error) {
	var sb strings.Builder
	jumps := 0
	next := -1 // позиция после имени в исходном потоке
	for {
		if off < 0 || off >= len(data) {
			return "", 0, fmt.Errorf("names: имя DNS выходит за границы пакета")
		}
		l := int(data[off])
		switch {
		case l == 0:
			off++
			if next < 0 {
				next = off
			}
			name := sb.String()
			if name == "" {
				return "", 0, fmt.Errorf("names: пустое имя DNS")
			}
			if len(name) > 253 {
				return "", 0, fmt.Errorf("names: имя DNS длиннее 253 символов")
			}
			return name, next, nil
		case l&0xc0 == 0xc0:
			if off+1 >= len(data) {
				return "", 0, fmt.Errorf("names: обрезанный указатель DNS")
			}
			if next < 0 {
				next = off + 2
			}
			jumps++
			if jumps > maxLabelJumps {
				return "", 0, fmt.Errorf("names: петля компрессионных указателей")
			}
			off = int(binary.BigEndian.Uint16(data[off:off+2]) & 0x3fff)
		case l&0xc0 != 0:
			return "", 0, fmt.Errorf("names: неподдерживаемый тип метки 0x%02x", data[off])
		default:
			off++
			if off+l > len(data) {
				return "", 0, fmt.Errorf("names: метка DNS выходит за границы пакета")
			}
			for _, c := range data[off : off+l] {
				if c < 0x20 || c == 0x7f {
					return "", 0, fmt.Errorf("names: управляющий символ 0x%02x в имени DNS", c)
				}
			}
			if sb.Len() > 0 {
				sb.WriteByte('.')
			}
			sb.Write(data[off : off+l])
			off += l
		}
	}
}

// skipDNSName пропускает имя в проводном формате, возвращая позицию
// после имени (без распаковки текста).
func skipDNSName(data []byte, off int) (int, error) {
	_, next, err := readDNSName(data, off)
	return next, err
}
