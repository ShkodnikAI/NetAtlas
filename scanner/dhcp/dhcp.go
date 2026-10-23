// Package dhcp разбирает файлы DHCP-аренд, выгруженные с роутера:
// формат isc (dhcpd.leases) и csv. Источник аренд — файл-выгрузка,
// а не опрос роутера: разбор файла работает с любой моделью и не
// создаёт сетевого трафика.
//
// Аренды — недоверенные данные: MAC нормализуется (model.NormalizeMAC),
// IP проверяется разбором netip, мусорные и неполные записи
// пропускаются и считаются в Skipped; ввод любого содержания не
// вызывает панику. Проверку имён (model.NewName) выполняет этап
// слияния в пакете scanner — здесь имя лишь извлекается как строка.
package dhcp

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"time"

	"github.com/ShkodnikAI/NetAtlas/internal/model"
)

// MaxInputSize — лимит размера входа: 5 МБ. Файл выгрузки аренд
// приходит извне, поэтому чтение ограничено, чтобы гигабайтный
// файл не исчерпал память.
const MaxInputSize = 5 << 20

// Lease — одна DHCP-аренда из файла-выгрузки. MAC приведён к
// каноническому виду aa:bb:cc:dd:ee:ff; IP — строка, прошедшая
// netip.ParseAddr; Expires — время окончания (ноль для «ends never»
// и пустого значения в csv); SSID заполнен, только если он был в файле.
type Lease struct {
	MAC      string
	IP       string
	Hostname string
	SSID     string
	Expires  time.Time
}

// Result — итог разбора файла аренд. Счётчик Skipped считает
// пропущенные записи: неполные блоки isc, строки csv без MAC/IP,
// записи с мусорной датой и мусорные строки вне блоков isc.
type Result struct {
	Leases  []Lease
	Skipped int
}

// ParseLeases читает аренды из r в формате format («isc» или «csv»).
// Ошибки: неизвестный формат, вход больше MaxInputSize, ошибка чтения;
// мусор внутри входа ошибкой не считается — он пропускается и
// учитывается в Result.Skipped. Формат проверяется до чтения входа.
func ParseLeases(r io.Reader, format string) (Result, error) {
	var parse func([]byte) (Result, error)
	switch format {
	case "isc":
		parse = parseISC
	case "csv":
		parse = parseCSV
	default:
		return Result{}, fmt.Errorf("dhcp: неизвестный формат %q (ждём isc или csv)", format)
	}
	data, err := readLimited(r)
	if err != nil {
		return Result{}, err
	}
	res, err := parse(data)
	if err != nil {
		return Result{}, err
	}
	if res.Leases == nil {
		res.Leases = []Lease{}
	}
	return res, nil
}

// readLimited читает вход целиком, но не более MaxInputSize+1 байта:
// лишний байт означает превышение лимита.
func readLimited(r io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxInputSize+1))
	if err != nil {
		return nil, fmt.Errorf("dhcp: чтение входа: %w", err)
	}
	if len(data) > MaxInputSize {
		return nil, fmt.Errorf("dhcp: вход больше лимита %d МБ", MaxInputSize>>20)
	}
	return data, nil
}

// parseISC разбирает dhcpd.leases: блоки «lease <ip> { … }» с полями
// hardware ethernet, client-hostname и ends (включая «ends never»).
// Прочие строки внутри блока (starts, binding state, option …) —
// нормальная часть формата и игнорируются. Блок считается записью:
// он принимается, только если в нём есть корректные MAC и IP и его
// дата ends разбирается; иначе блок целиком пропускается со счётчиком.
// Мусорные строки вне блоков считаются построчно; блок без закрывающей
// скобки в конце файла пропускается.
func parseISC(data []byte) (Result, error) {
	res := Result{Leases: []Lease{}}
	skip := func() { res.Skipped++ }

	var (
		cur       Lease
		inBlock   bool
		haveMAC   bool
		endsValid bool
	)
	finish := func() {
		if inBlock && haveMAC && endsValid && cur.IP != "" {
			res.Leases = append(res.Leases, cur)
		} else if inBlock {
			skip()
		}
		inBlock, haveMAC, endsValid = false, false, false
		cur = Lease{}
	}

	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if !inBlock {
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) >= 3 && fields[0] == "lease" && fields[len(fields)-1] == "{" {
				ip := strings.TrimSpace(strings.Join(fields[1:len(fields)-1], " "))
				if a, err := netip.ParseAddr(ip); err == nil {
					cur.IP = a.String()
				}
				inBlock = true
				continue
			}
			skip() // мусорная строка вне блока
			continue
		}
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if line == "}" {
			finish()
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "hardware":
			// «hardware ethernet aa:bb:…;» — только ethernet несёт MAC.
			if len(fields) == 3 && fields[1] == "ethernet" {
				mac := strings.TrimSuffix(fields[2], ";")
				if m, err := model.NormalizeMAC(mac); err == nil {
					cur.MAC, haveMAC = m, true
				}
			}
		case "client-hostname":
			name := strings.TrimSuffix(strings.Join(fields[1:], " "), ";")
			name = strings.TrimSpace(name)
			cur.Hostname = strings.Trim(name, `"`)
		case "ends":
			rest := strings.TrimSuffix(strings.TrimSpace(strings.TrimPrefix(line, "ends")), ";")
			rest = strings.TrimSpace(rest)
			if rest == "never" {
				endsValid = true
				continue
			}
			// «ends 3 2026/10/21 12:00:00» — день недели игнорируется;
			// допускается и вариант «дата время» без дня недели.
			parts := strings.Fields(rest)
			if len(parts) == 3 {
				rest = parts[1] + " " + parts[2]
			} else if len(parts) == 2 {
				rest = parts[0] + " " + parts[1]
			} else {
				continue
			}
			if t, err := time.Parse("2006/01/02 15:04:05", rest); err == nil {
				cur.Expires, endsValid = t, true
			}
		}
	}
	finish() // блок без закрывающей скобки — неполная запись
	return res, nil
}

// parseCSV разбирает файл с заголовком mac,ip,hostname,ssid,expires;
// столбцы ssid и expires необязательны. Столбцы сопоставляются по
// именам заголовка, поэтому порядок значения не имеет; неизвестные
// столбцы игнорируются. Строка пропускается со счётчиком, если у неё
// не хватает полей, MAC или IP некорректны, а expires не пуст и не
// разбирается по RFC 3339. Пустое значение expires означает нулевое
// время. Файл без заголовка — ошибка; пустой файл — пустой результат.
func parseCSV(data []byte) (Result, error) {
	res := Result{Leases: []Lease{}}
	data = bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF}) // BOM из Excel
	r := csv.NewReader(bytes.NewReader(data))
	r.FieldsPerRecord = -1
	rows, err := r.ReadAll()
	if err != nil {
		return Result{}, fmt.Errorf("dhcp: csv: %w", err)
	}
	if len(rows) == 0 {
		return res, nil
	}
	head := make([]string, len(rows[0]))
	for i, c := range rows[0] {
		head[i] = strings.ToLower(strings.TrimSpace(c))
	}
	idx := func(name string) int {
		for i, h := range head {
			if h == name {
				return i
			}
		}
		return -1
	}
	iMAC, iIP, iHost := idx("mac"), idx("ip"), idx("hostname")
	iSSID, iExp := idx("ssid"), idx("expires")
	if iMAC < 0 || iIP < 0 || iHost < 0 {
		return Result{}, fmt.Errorf("dhcp: csv: в заголовке нет столбцов mac, ip, hostname")
	}
	cell := func(row []string, i int) string {
		if i < 0 || i >= len(row) {
			return ""
		}
		return strings.TrimSpace(row[i])
	}
	for _, row := range rows[1:] {
		if len(row) != len(head) {
			res.Skipped++ // рваная строка: столбцов не как в заголовке
			continue
		}
		mac, err := model.NormalizeMAC(cell(row, iMAC))
		if err != nil {
			res.Skipped++
			continue
		}
		ipRaw := cell(row, iIP)
		a, err := netip.ParseAddr(ipRaw)
		if err != nil {
			res.Skipped++
			continue
		}
		lease := Lease{MAC: mac, IP: a.String(), Hostname: cell(row, iHost), SSID: cell(row, iSSID)}
		if exp := cell(row, iExp); exp != "" {
			t, err := time.Parse(time.RFC3339, exp)
			if err != nil {
				res.Skipped++
				continue
			}
			lease.Expires = t
		}
		res.Leases = append(res.Leases, lease)
	}
	return res, nil
}
