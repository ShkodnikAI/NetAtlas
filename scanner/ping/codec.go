// Package ping — активная проверка живости адресов ICMP-эхом.
//
// Границы применения обеспечиваются вызывающей стороной (scanner):
// пакет отвечает только за протокол, не за список адресов.
package ping

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// ErrNotEcho — пакет ICMP не является эхо-ответом (в том числе
// «destination unreachable», тип 3): хост не ответил эхом.
var ErrNotEcho = errors.New("ping: пакет не является эхо-ответом")

// Reply — разобранный ICMP echo reply.
type Reply struct {
	ID      uint16
	Seq     uint16
	Payload []byte
}

// EchoRequest собирает ICMP echo request: тип 8, код 0, контрольная
// сумма по RFC 1071, идентификатор, номер, полезная нагрузка.
func EchoRequest(id, seq uint16, payload []byte) []byte {
	b := make([]byte, 8+len(payload))
	b[0] = 8 // echo request
	b[1] = 0 // код 0
	binary.BigEndian.PutUint16(b[4:6], id)
	binary.BigEndian.PutUint16(b[6:8], seq)
	copy(b[8:], payload)
	binary.BigEndian.PutUint16(b[2:4], Checksum(b))
	return b
}

// ParseEchoReply разбирает ICMP echo reply. Тип обязан быть 0, код 0,
// длина не меньше 8 байт, контрольная сумма обязана сходиться.
// Любой другой тип — ErrNotEcho; обрезанный или мусорный пакет — ошибка.
func ParseEchoReply(data []byte) (Reply, error) {
	if len(data) < 8 {
		return Reply{}, fmt.Errorf("ping: короткий пакет: %d байт, нужно не меньше 8", len(data))
	}
	if Checksum(data) != 0 {
		return Reply{}, fmt.Errorf("ping: контрольная сумма не сошлась")
	}
	if data[0] != 0 {
		return Reply{}, fmt.Errorf("%w: тип %d", ErrNotEcho, data[0])
	}
	if data[1] != 0 {
		return Reply{}, fmt.Errorf("ping: код %d, нужен 0", data[1])
	}
	return Reply{
		ID:      binary.BigEndian.Uint16(data[4:6]),
		Seq:     binary.BigEndian.Uint16(data[6:8]),
		Payload: append([]byte(nil), data[8:]...),
	}, nil
}

// Checksum считает контрольную сумму по RFC 1071: дополнение до единицы
// суммы дополнений до единицы 16-битных слов; непарный байт — старшим.
func Checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}
