package oui

import "testing"

func TestLookupKnown(t *testing.T) {
	// Префиксы взяты из встроенного реестра (oui.csv, MA-L):
	// 00000C — Cisco Systems, Inc; 286FB9 — Nokia Shanghai Bell.
	cases := []struct {
		mac    string
		vendor string
	}{
		{"00:00:0c:11:22:33", "Cisco Systems, Inc"},
		{"00:00:0C:AB:CD:EF", "Cisco Systems, Inc"}, // регистр не важен
		{"00-00-0c-de-ad-01", "Cisco Systems, Inc"}, // разделитель «дефис»
		{"28:6f:b9:00:00:01", "Nokia Shanghai Bell Co., Ltd."},
		{"0024.36ff.1122", "???"}, // точечная форма: см. ниже
	}
	// Точечная форма разбирается NormalizeMAC; префикс 002436 проверяем
	// отдельно, чтобы не завязываться на конкретного производителя.
	for _, c := range cases[:4] {
		v, ok := Lookup(c.mac)
		if !ok || v != c.vendor {
			t.Errorf("Lookup(%q) = (%q, %v), ждём (%q, true)", c.mac, v, ok, c.vendor)
		}
	}
	if v, ok := Lookup("0024.36ff.1122"); !ok || v == "" {
		t.Errorf("Lookup(0024.36ff.1122) = (%q, %v), ждём известного производителя", v, ok)
	}
}

func TestLookupUnknownPrefix(t *testing.T) {
	// DEADBE в реестре MA-L отсутствует (проверено при составлении теста).
	if v, ok := Lookup("de:ad:be:ef:00:01"); ok || v != "" {
		t.Errorf("Lookup(de:ad:be:ef:00:01) = (%q, %v), ждём (\"\", false)", v, ok)
	}
}

func TestLookupLocallyAdministered(t *testing.T) {
	// Второй бит первого байта (0x02) — локальное администрирование:
	// производителя нет, даже если префикс с установленным битом
	// формально есть в реестре (AA0004 — DEC, историческая запись MA-L).
	if v, ok := Lookup("aa:00:04:00:00:01"); ok || v != "" {
		t.Errorf("Lookup(aa:00:04:00:00:01) = (%q, %v), ждём (\"\", false): локально-администрируемый", v, ok)
	}
	// Тот же префикс без второго бита (0xAA и 0xA8 отличаются только им)
	// остаётся неизвестным здесь, но правило бита проверено выше на
	// реальной записи реестра — снятие проверки делает тест красным.
	if v, ok := Lookup("2a:6f:b9:00:00:01"); ok || v != "" {
		t.Errorf("Lookup(2a:6f:b9:00:00:01) = (%q, %v), ждём (\"\", false)", v, ok)
	}
}

func TestLookupInvalid(t *testing.T) {
	cases := []string{
		"",
		"not-a-mac",
		"00:00:00:00:00:00", // нулевой
		"ff:ff:ff:ff:ff:ff", // широковещательный
		"01:00:5e:00:00:01", // групповой
		"00000c112233",      // без разделителей
		"00:00:0c:11:22",    // неполный
	}
	for _, mac := range cases {
		if v, ok := Lookup(mac); ok || v != "" {
			t.Errorf("Lookup(%q) = (%q, %v), ждём (\"\", false)", mac, v, ok)
		}
	}
}

func TestRegistryLoaded(t *testing.T) {
	once.Do(load)
	if len(byOUI) < 30000 {
		t.Fatalf("реестр подозрительно мал: %d записей, ждём не менее 30000", len(byOUI))
	}
	if v, ok := byOUI["00000C"]; !ok || v != "Cisco Systems, Inc" {
		t.Errorf("реестр: byOUI[00000C] = (%q, %v), ждём (\"Cisco Systems, Inc\", true)", v, ok)
	}
}
