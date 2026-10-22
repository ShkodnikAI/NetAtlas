// Package names — разрешение имён устройств: NetBIOS (UDP/137),
// mDNS (UDP/5353) и SSDP (UDP/1900).
//
// Все ответы сети считаются недоверенными данными: парсеры не паникуют
// на обрезанных и мусорных пакетах, строки ограничены по длине.
// Проверку границ (scope) выполняет вызывающая сторона — пакет
// отвечает только за протоколы.
package names

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// NBNameLen — длина имени NetBIOS без байта суффикса (RFC 1002).
const NBNameLen = 15

// encodedNameLen — длина имени в проводном формате (16 байт → 32 символа).
const encodedNameLen = 32

// encodeNetBIOSName кодирует имя по RFC 1002 (раздел 4.2): верхний
// регистр, только печатаемые ASCII, паддинг пробелами до 15 байт,
// нулевой байт суффикса; каждая пара полубайтов кодируется символом
// 'A' + значение полубайта. Возвращает 32 символа.
func encodeNetBIOSName(name string) ([]byte, error) {
	name = strings.ToUpper(name)
	b := []byte(name)
	if len(b) > NBNameLen {
		return nil, fmt.Errorf("names: имя NetBIOS длиннее %d байт: %q", NBNameLen, name)
	}
	for _, c := range b {
		if c < 0x20 || c > 0x7e {
			return nil, fmt.Errorf("names: имя NetBIOS содержит недопустимый символ 0x%02x", c)
		}
	}
	padded := make([]byte, 16)
	copy(padded, b)
	for i := len(b); i < NBNameLen; i++ {
		padded[i] = 0x20
	}
	padded[NBNameLen] = 0x00 // байт суффикса

	out := make([]byte, encodedNameLen)
	for i, v := range padded {
		out[i*2] = byte('A' + (v >> 4))
		out[i*2+1] = byte('A' + (v & 0x0f))
	}
	return out, nil
}

// decodeNetBIOSName декодирует 32 символа обратно в имя: полубайты
// из символов, первые 15 байт — имя (пробелы по краям тримятся),
// шестнадцатый байт — суффикс, отбрасывается.
func decodeNetBIOSName(enc []byte) (string, error) {
	if len(enc) < encodedNameLen {
		return "", fmt.Errorf("names: закодированное имя короче %d символов: %d", encodedNameLen, len(enc))
	}
	raw := make([]byte, 16)
	for i := 0; i < 16; i++ {
		hi, ok1 := nibble(enc[i*2])
		lo, ok2 := nibble(enc[i*2+1])
		if !ok1 || !ok2 {
			return "", fmt.Errorf("names: недопустимый символ в закодированном имени: 0x%02x/0x%02x", enc[i*2], enc[i*2+1])
		}
		raw[i] = hi<<4 | lo
	}
	return strings.TrimSpace(string(raw[:NBNameLen])), nil
}

func nibble(c byte) (byte, bool) {
	if c >= 'A' && c <= 'P' {
		return c - 'A', true
	}
	return 0, false
}

// EncodeNameQuery собирает NBNS-запрос имени (UDP/137): заголовок с
// TRN ID, флаги 0x0100 (стандартный запрос), один вопрос: закодированное
// имя, QTYPE 0x0020 (NB), QCLASS 0x0001 (IN).
func EncodeNameQuery(name string, trnID uint16) ([]byte, error) {
	enc, err := encodeNetBIOSName(name)
	if err != nil {
		return nil, err
	}
	b := make([]byte, 0, 12+1+encodedNameLen+1+4)
	b = appendUint16(b, trnID)
	b = appendUint16(b, 0x0100) // флаги: стандартный запрос
	b = appendUint16(b, 1)      // QDCOUNT
	b = appendUint16(b, 0)      // ANCOUNT
	b = appendUint16(b, 0)      // NSCOUNT
	b = appendUint16(b, 0)      // ARCOUNT
	b = append(b, 0x20)         // длина метки: 32 символа
	b = append(b, enc...)
	b = append(b, 0x00)         // конец имени
	b = appendUint16(b, 0x0020) // QTYPE NB
	b = appendUint16(b, 0x0001) // QCLASS IN
	return b, nil
}

// DecodeNameResponse разбирает NBNS-ответ: QR=1, RCODE=0, TRN ID
// совпадает; имя берётся из owner-имени первого ответа (сжимающий
// указатель 0xC0 поддерживается). Чужой ID, RCODE ≠ 0, отсутствие
// ответов и мусор дают ошибку.
func DecodeNameResponse(data []byte, trnID uint16) (string, error) {
	if len(data) < 12 {
		return "", fmt.Errorf("names: короткий NBNS-ответ: %d байт", len(data))
	}
	if id := binary.BigEndian.Uint16(data[0:2]); id != trnID {
		return "", fmt.Errorf("names: чужой TRN ID: %#04x, хочу %#04x", id, trnID)
	}
	flags := binary.BigEndian.Uint16(data[2:4])
	if flags&0x8000 == 0 {
		return "", fmt.Errorf("names: это не ответ (QR=0)")
	}
	if rcode := flags & 0x000f; rcode != 0 {
		return "", fmt.Errorf("names: RCODE=%d", rcode)
	}
	qd := int(binary.BigEndian.Uint16(data[4:6]))
	an := int(binary.BigEndian.Uint16(data[6:8]))
	if an == 0 {
		return "", fmt.Errorf("names: в ответе нет записей")
	}
	off := 12
	for i := 0; i < qd; i++ { // вопросы пропускаются
		var err error
		if off, err = skipQuestion(data, off); err != nil {
			return "", err
		}
	}
	if off >= len(data) {
		return "", fmt.Errorf("names: ответы выходят за границы пакета")
	}
	// Owner-имя первого ответа: указатель или инлайн-закодированное имя.
	if data[off] == 0xc0 {
		if off+1 >= len(data) {
			return "", fmt.Errorf("names: обрезанный указатель имени")
		}
		ptr := int(binary.BigEndian.Uint16(data[off:off+2]) & 0x3fff)
		return decodeNameAt(data, ptr)
	}
	return decodeNameAt(data, off)
}

// decodeNameAt разбирает имя в проводном формате NBNS с позиции off:
// байт длины 0x20, 32 символа, нулевой терминатор.
func decodeNameAt(data []byte, off int) (string, error) {
	if off < 0 || off >= len(data) || data[off] != 0x20 {
		return "", fmt.Errorf("names: ожидается метка длиной 32 на позиции %d", off)
	}
	enc := data[off+1 : off+1+encodedNameLen]
	name, err := decodeNetBIOSName(enc)
	if err != nil {
		return "", err
	}
	return name, nil
}

// skipQuestion пропускает вопрос: закодированное имя (32 + терминатор)
// или другой формат метки, затем QTYPE и QCLASS.
func skipQuestion(data []byte, off int) (int, error) {
	if off >= len(data) {
		return 0, fmt.Errorf("names: вопрос выходит за границы пакета")
	}
	if data[off] == 0x20 {
		if off+1+encodedNameLen+1 > len(data) {
			return 0, fmt.Errorf("names: имя вопроса обрезано")
		}
		off += 1 + encodedNameLen
		if data[off] != 0x00 {
			return 0, fmt.Errorf("names: имя вопроса не завершено нулевым байтом")
		}
		off++
	} else {
		// прочие метки: до нулевого байта
		for off < len(data) && data[off] != 0x00 {
			off++
		}
		if off >= len(data) {
			return 0, fmt.Errorf("names: незавершённое имя вопроса")
		}
		off++
	}
	if off+4 > len(data) {
		return 0, fmt.Errorf("names: вопрос обрезан")
	}
	return off + 4, nil
}

// QTypeNBStat — QTYPE запроса состояния узла (Node Status, NBSTAT):
// именно он возвращает имена хоста (аналог nbtstat -A). Обычный
// NB-запрос (0x0020) возвращает owner-имя того, что запросили, и для
// обнаружения имён бесполезен.
const QTypeNBStat = 0x0021

// EncodeNodeStatusQuery собирает NBSTAT-запрос состояния узла
// (UDP/137): wildcard-имя «*» (по RFC 1002 паддинг пробелами),
// QTYPE 0x0021, QCLASS 0x0001.
func EncodeNodeStatusQuery(trnID uint16) ([]byte, error) {
	enc, err := encodeNetBIOSName("*")
	if err != nil {
		return nil, err
	}
	b := make([]byte, 0, 12+1+encodedNameLen+1+4)
	b = appendUint16(b, trnID)
	b = appendUint16(b, 0x0100) // флаги: стандартный запрос
	b = appendUint16(b, 1)      // QDCOUNT
	b = appendUint16(b, 0)      // ANCOUNT
	b = appendUint16(b, 0)      // NSCOUNT
	b = appendUint16(b, 0)      // ARCOUNT
	b = append(b, 0x20)         // длина метки: 32 символа
	b = append(b, enc...)
	b = append(b, 0x00) // конец имени
	b = appendUint16(b, QTypeNBStat)
	b = appendUint16(b, 0x0001) // QCLASS IN
	return b, nil
}

// DecodeNodeStatusResponse разбирает NBSTAT-ответ: TRN ID совпадает,
// QR=1, RCODE=0; из rdata первой NBSTAT-записи читается таблица имён
// (число имён, затем по 18 байт: 15 байт имени, байт суффикса, 2 байта
// флагов; в конце — MAC, 6 байт, здесь не используется). Имена
// обрезаются по краям, пустые и с управляющими символами отбрасываются,
// дубликаты схлопываются. Мусор и обрезка — ошибка без паники.
func DecodeNodeStatusResponse(data []byte, trnID uint16) ([]string, error) {
	if len(data) < 12 {
		return nil, fmt.Errorf("names: короткий NBSTAT-ответ: %d байт", len(data))
	}
	if id := binary.BigEndian.Uint16(data[0:2]); id != trnID {
		return nil, fmt.Errorf("names: чужой TRN ID: %#04x, хочу %#04x", id, trnID)
	}
	flags := binary.BigEndian.Uint16(data[2:4])
	if flags&0x8000 == 0 {
		return nil, fmt.Errorf("names: это не ответ (QR=0)")
	}
	if rcode := flags & 0x000f; rcode != 0 {
		return nil, fmt.Errorf("names: RCODE=%d", rcode)
	}
	qd := int(binary.BigEndian.Uint16(data[4:6]))
	an := int(binary.BigEndian.Uint16(data[6:8]))
	if an == 0 {
		return nil, fmt.Errorf("names: в ответе нет записей")
	}
	off := 12
	for i := 0; i < qd; i++ {
		var err error
		if off, err = skipQuestion(data, off); err != nil {
			return nil, err
		}
	}
	if off >= len(data) {
		return nil, fmt.Errorf("names: ответы выходят за границы пакета")
	}
	// Owner-имя первого ответа пропускается (указатель или инлайн-имя).
	if data[off] == 0xc0 {
		if off+1 >= len(data) {
			return nil, fmt.Errorf("names: обрезанный указатель имени")
		}
		off += 2
	} else if data[off] == 0x20 {
		if off+1+encodedNameLen+1 > len(data) {
			return nil, fmt.Errorf("names: обрезанное имя в ответе")
		}
		off += 1 + encodedNameLen + 1
	} else {
		return nil, fmt.Errorf("names: неожидаемый формат имени на позиции %d: 0x%02x", off, data[off])
	}
	if off+10 > len(data) {
		return nil, fmt.Errorf("names: запись NBSTAT обрезана")
	}
	rrType := binary.BigEndian.Uint16(data[off : off+2])
	rdlen := int(binary.BigEndian.Uint16(data[off+8 : off+10]))
	if rrType != QTypeNBStat {
		return nil, fmt.Errorf("names: тип записи 0x%04x, хочу NBSTAT", rrType)
	}
	off += 10
	if off+rdlen > len(data) || rdlen < 1 {
		return nil, fmt.Errorf("names: rdata NBSTAT выходит за границы пакета")
	}
	rdata := data[off : off+rdlen]
	count := int(rdata[0])
	names := make([]string, 0, count)
	seen := make(map[string]bool, count)
	for i := 0; i < count; i++ {
		base := 1 + i*18
		if base+18 > len(rdata) {
			return nil, fmt.Errorf("names: запись имён %d обрезана", i)
		}
		raw := strings.TrimSpace(string(rdata[base : base+NBNameLen]))
		if raw == "" {
			continue
		}
		bad := false
		for _, c := range []byte(raw) {
			if c < 0x20 || c == 0x7f {
				bad = true
				break
			}
		}
		if bad || seen[raw] {
			continue
		}
		seen[raw] = true
		names = append(names, raw)
	}
	return names, nil
}

func appendUint16(b []byte, v uint16) []byte {
	return append(b, byte(v>>8), byte(v))
}
