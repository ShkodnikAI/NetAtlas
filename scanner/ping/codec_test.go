package ping

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

func TestEchoRequestShape(t *testing.T) {
	payload := []byte{1, 2, 3, 4}
	req := EchoRequest(0x1234, 7, payload)
	if len(req) != 8+len(payload) {
		t.Fatalf("длина = %d, хочу %d", len(req), 8+len(payload))
	}
	if req[0] != 8 {
		t.Errorf("тип = %d, хочу 8 (echo request)", req[0])
	}
	if req[1] != 0 {
		t.Errorf("код = %d, хочу 0", req[1])
	}
	if got := binary.BigEndian.Uint16(req[4:6]); got != 0x1234 {
		t.Errorf("ID = %#x, хочу %#x", got, 0x1234)
	}
	if got := binary.BigEndian.Uint16(req[6:8]); got != 7 {
		t.Errorf("Seq = %#x, хочу 7", got)
	}
	if !bytes.Equal(req[8:], payload) {
		t.Errorf("полезная нагрузка изменилась: %v", req[8:])
	}
	// Контрольная сумма готового пакета обязана давать ноль.
	if cs := Checksum(req); cs != 0 {
		t.Errorf("контрольная сумма готового пакета = %#x, хочу 0", cs)
	}
}

func TestChecksumRFC1071Vector(t *testing.T) {
	// Классический пример из RFC 1071: 0001 f203 f4f5 f6f7 → 220d.
	data := []byte{0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7}
	if got := Checksum(data); got != 0x220d {
		t.Errorf("Checksum = %#04x, хочу 0x220d", got)
	}
}

func TestParseEchoReplyRoundTrip(t *testing.T) {
	payload := []byte("payload-01")
	req := EchoRequest(0xabcd, 42, payload)
	// Превращаем запрос в ответ: тип 0, контрольная сумма пересчитана
	// (поле суммы сначала обнуляется — сумма считается при нулевом поле).
	req[0] = 0
	binary.BigEndian.PutUint16(req[2:4], 0)
	binary.BigEndian.PutUint16(req[2:4], Checksum(req))

	rep, err := ParseEchoReply(req)
	if err != nil {
		t.Fatalf("ParseEchoReply: неожиданная ошибка: %v", err)
	}
	if rep.ID != 0xabcd {
		t.Errorf("ID = %#x, хочу 0xabcd", rep.ID)
	}
	if rep.Seq != 42 {
		t.Errorf("Seq = %d, хочу 42", rep.Seq)
	}
	if !bytes.Equal(rep.Payload, payload) {
		t.Errorf("Payload = %v, хочу %v", rep.Payload, payload)
	}
}

func TestParseEchoReplyNotEcho(t *testing.T) {
	// destination unreachable: тип 3, код 1, валидная контрольная сумма.
	data := []byte{3, 1, 0, 0, 0xaa, 0xbb, 0x00, 0x01}
	binary.BigEndian.PutUint16(data[2:4], Checksum(data))
	_, err := ParseEchoReply(data)
	if !errors.Is(err, ErrNotEcho) {
		t.Errorf("ожидалась ErrNotEcho, получено: %v", err)
	}
}

func TestParseEchoReplyBadChecksum(t *testing.T) {
	rep := EchoRequest(1, 1, []byte{9, 9, 9, 9})
	rep[0] = 0
	binary.BigEndian.PutUint16(rep[2:4], 0)
	binary.BigEndian.PutUint16(rep[2:4], Checksum(rep))
	rep[len(rep)-1] ^= 0xff // портим нагрузку, сумму не пересчитываем
	if _, err := ParseEchoReply(rep); err == nil {
		t.Error("битая контрольная сумма: ожидалась ошибка")
	}
}

func TestParseEchoReplyShort(t *testing.T) {
	for _, n := range []int{0, 3, 7} {
		data := make([]byte, n)
		if _, err := ParseEchoReply(data); err == nil {
			t.Errorf("пакет из %d байт: ожидалась ошибка", n)
		}
	}
}
