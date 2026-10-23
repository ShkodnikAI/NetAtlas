// Package oui определяет производителя устройства по MAC-адресу
// по реестру IEEE MA-L (файл oui.csv), встроенному в бинарь через
// go:embed. Никаких сетевых запросов: таблица целиком локальная.
//
// Lookup учитывает семантику MAC: локально-администрируемые адреса
// (второй бит первого байта) не несут сведений о производителе и
// дают ok=false, как и неверные, групповые и неизвестные префиксы.
package oui

import (
	_ "embed"
	"encoding/csv"
	"strconv"
	"strings"
	"sync"

	"github.com/ShkodnikAI/NetAtlas/internal/model"
)

//go:embed oui.csv
var registryCSV string

var (
	once  sync.Once
	byOUI map[string]string
)

// load разбирает встроенный реестр один раз при первом Lookup.
// Формат файла: CSV с заголовком Registry,Assignment,Organization
// Name,Organization Address; используются столбцы Assignment (шесть
// шестнадцатеричных цифр) и Organization Name. Строки без корректного
// префикса или без названия пропускаются; разбор не может вызвать
// панику на данных реестра — встроенный файл проверен тестами.
func load() {
	byOUI = make(map[string]string)
	r := csv.NewReader(strings.NewReader(registryCSV))
	r.FieldsPerRecord = -1
	rows, err := r.ReadAll()
	if err != nil {
		return
	}
	for _, row := range rows {
		if len(row) < 3 || row[0] != "MA-L" {
			continue
		}
		assign := strings.ToUpper(strings.TrimSpace(row[1]))
		org := strings.TrimSpace(row[2])
		if len(assign) != 6 || org == "" {
			continue
		}
		if _, err := strconv.ParseUint(assign, 16, 32); err != nil {
			continue
		}
		byOUI[assign] = org
	}
}

// Lookup возвращает производителя по первым трём байтам MAC-адреса.
// ok=false для: неверного MAC, группового MAC (NormalizeMAC его
// отвергает), локально-администрируемого MAC (второй бит первого
// байта установлен) и префикса, которого нет в реестре MA-L.
func Lookup(mac string) (string, bool) {
	once.Do(load)
	m, err := model.NormalizeMAC(mac)
	if err != nil {
		return "", false
	}
	first, err := strconv.ParseUint(m[:2], 16, 8)
	if err != nil {
		return "", false
	}
	if first&0x02 != 0 {
		return "", false // локально-администрируемый: производителя нет
	}
	prefix := strings.ReplaceAll(m, ":", "")[:6]
	vendor, ok := byOUI[strings.ToUpper(prefix)]
	return vendor, ok
}
