package dhcp

import (
	"os"
	"strings"
	"testing"
	"time"
)

func mustParse(t *testing.T, input, format string) Result {
	t.Helper()
	res, err := ParseLeases(strings.NewReader(input), format)
	if err != nil {
		t.Fatalf("ParseLeases(%q): неожиданная ошибка: %v", format, err)
	}
	if res.Leases == nil {
		t.Fatalf("ParseLeases(%q): Leases == nil, ждём непустой срез", format)
	}
	return res
}

func TestParseLeasesISCFixture(t *testing.T) {
	r := mustParse(t, readFixture(t, "leases_isc.txt"), "isc")
	if len(r.Leases) != 3 {
		t.Fatalf("isc: leases = %d, ждём 3; результат %+v", len(r.Leases), r.Leases)
	}
	if r.Skipped != 2 { // мусорная строка + блок без hardware
		t.Errorf("isc: skipped = %d, ждём 2", r.Skipped)
	}
	l := r.Leases[0]
	if l.MAC != "aa:bb:cc:dd:ee:f0" {
		t.Errorf("isc: MAC = %q, ждём aa:bb:cc:dd:ee:f0 (регистр нормализован)", l.MAC)
	}
	if l.IP != "192.0.2.10" || l.Hostname != "lab-laptop" {
		t.Errorf("isc: запись 0 = %+v, ждём IP 192.0.2.10 и hostname lab-laptop", l)
	}
	want := time.Date(2026, 10, 21, 20, 0, 0, 0, time.UTC)
	if !l.Expires.Equal(want) {
		t.Errorf("isc: Expires = %v, ждём %v", l.Expires, want)
	}
	if r.Leases[1].Hostname != "" {
		t.Errorf("isc: запись 1: hostname = %q, ждём пустое", r.Leases[1].Hostname)
	}
	if !r.Leases[1].Expires.IsZero() {
		t.Errorf("isc: запись 1: Expires = %v, ждём нулевое (ends never)", r.Leases[1].Expires)
	}
	if r.Leases[2].MAC != "00:00:0c:11:22:33" {
		t.Errorf("isc: MAC из дефисной формы = %q, ждём 00:00:0c:11:22:33", r.Leases[2].MAC)
	}
}

func TestParseLeasesCSVFixture(t *testing.T) {
	r := mustParse(t, readFixture(t, "leases_csv.csv"), "csv")
	if len(r.Leases) != 3 {
		t.Fatalf("csv: leases = %d, ждём 3; результат %+v", len(r.Leases), r.Leases)
	}
	if r.Skipped != 3 { // IP в столбце mac, мусорная дата, некорректный IP
		t.Errorf("csv: skipped = %d, ждём 3", r.Skipped)
	}
	l := r.Leases[0]
	if l.SSID != "Office-WiFi" {
		t.Errorf("csv: ssid = %q, ждём Office-WiFi", l.SSID)
	}
	want := time.Date(2026, 10, 21, 20, 0, 0, 0, time.UTC)
	if !l.Expires.Equal(want) {
		t.Errorf("csv: Expires = %v, ждём %v (RFC 3339)", l.Expires, want)
	}
	if r.Leases[2].MAC != "de:ad:be:ef:00:02" {
		t.Errorf("csv: MAC из дефисной формы = %q, ждём de:ad:be:ef:00:02", r.Leases[2].MAC)
	}
	if r.Leases[2].SSID != "" || !r.Leases[2].Expires.IsZero() {
		t.Errorf("csv: запись 2: ssid/expires = %q/%v, ждём пустые", r.Leases[2].SSID, r.Leases[2].Expires)
	}
}

func TestParseLeasesCSVMinimalHeader(t *testing.T) {
	r := mustParse(t, readFixture(t, "leases_csv_min.csv"), "csv")
	if len(r.Leases) != 1 || r.Skipped != 0 {
		t.Fatalf("csv-min: leases=%d skipped=%d, ждём 1 и 0", len(r.Leases), r.Skipped)
	}
	if r.Leases[0].Hostname != "nas-box" || r.Leases[0].SSID != "" {
		t.Errorf("csv-min: запись = %+v, ждём hostname nas-box без ssid", r.Leases[0])
	}
}

func TestParseLeasesEmptyInput(t *testing.T) {
	cases := []struct {
		name, format, input string
	}{
		{"isc пустой", "isc", ""},
		{"isc только комментарии", "isc", "# dhcpd.leases\n\n# конец\n"},
		{"csv пустой", "csv", ""},
		{"csv только заголовок", "csv", "mac,ip,hostname,ssid,expires\n"},
	}
	for _, c := range cases {
		r := mustParse(t, c.input, c.format)
		if len(r.Leases) != 0 || r.Skipped != 0 {
			t.Errorf("%s: leases=%d skipped=%d, ждём 0 и 0", c.name, len(r.Leases), r.Skipped)
		}
	}
}

func TestParseLeasesCSVNoHeader(t *testing.T) {
	_, err := ParseLeases(strings.NewReader("мусор без заголовка\n"), "csv")
	if err == nil || !strings.Contains(err.Error(), "заголовке") {
		t.Errorf("csv без заголовка: err = %v, ждём ошибку про заголовок", err)
	}
}

func TestParseLeasesUnknownFormat(t *testing.T) {
	_, err := ParseLeases(strings.NewReader(""), "xml")
	if err == nil || !strings.Contains(err.Error(), "неизвестный формат") {
		t.Errorf("формат xml: err = %v, ждём ошибку про неизвестный формат", err)
	}
}

func TestParseLeasesOverLimit(t *testing.T) {
	// Вход ровно в лимит (считая перевод строки) — не ошибка.
	atLimit := strings.Repeat("a", MaxInputSize-1) + "\n"
	if r := mustParse(t, atLimit, "isc"); r.Skipped != 1 {
		t.Errorf("вход ровно MaxInputSize: skipped = %d, ждём 1, ошибки быть не должно", r.Skipped)
	}
	// Один байт сверх лимита — ошибка.
	over := strings.Repeat("a", MaxInputSize) + "\n"
	_, err := ParseLeases(strings.NewReader(over), "isc")
	if err == nil || !strings.Contains(err.Error(), "лимит") {
		t.Errorf("вход больше лимита: err = %v, ждём ошибку про лимит", err)
	}
}

func TestParseLeasesHostileInput(t *testing.T) {
	nasty := []string{
		"\x00\x01\x02\xff\xfe",
		"lease {",
		"lease 1.2.3.4 {",
		"}",
		"} } }",
		"lease 192.0.2.1 { hardware ethernet }",
		"lease 192.0.2.1 { hardware ethernet zz:bb:cc:dd:ee:ff; }",
		"lease 192.0.2.1 { hardware ethernet aa:bb:cc:dd:ee:ff; ends 9 9999/99/99 99:99:99; }",
		"lease 192.0.2.1 { ends 3 2026/10/21 20:00:00; }",
		"lease 192.0.2.1 { ends; }",
		"lease 192.0.2.1 { client-hostname; }",
		"lease 192.0.2.1 { client-hostname \"незакрытая кавычка; }",
		strings.Repeat("lease 192.0.2.1 { hardware ethernet aa:bb:cc:dd:ee:ff; }", 1000),
		"hardware ethernet aa:bb:cc:dd:ee:ff;",
		"client-hostname \"вне блока\";",
	}
	for _, in := range nasty {
		func() {
			defer func() {
				if p := recover(); p != nil {
					t.Errorf("isc-вход %q: паника: %v", truncate(in), p)
				}
			}()
			if _, err := ParseLeases(strings.NewReader(in), "isc"); err != nil {
				t.Errorf("isc-вход %q: неожиданная ошибка %v", truncate(in), err)
			}
		}()
	}
	for _, in := range nasty {
		func() {
			defer func() {
				if p := recover(); p != nil {
					t.Errorf("csv-вход %q: паника: %v", truncate(in), p)
				}
			}()
			// Ошибки разбора допустимы, паники — нет.
			_, _ = ParseLeases(strings.NewReader(in), "csv")
		}()
	}
}

func TestParseLeasesISCUnterminatedBlock(t *testing.T) {
	in := "lease 192.0.2.30 {\n  hardware ethernet aa:bb:cc:dd:ee:55;\n"
	r := mustParse(t, in, "isc")
	if len(r.Leases) != 0 || r.Skipped != 1 {
		t.Errorf("незакрытый блок: leases=%d skipped=%d, ждём 0 и 1", len(r.Leases), r.Skipped)
	}
}

func readFixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatalf("фикстура %s: %v", name, err)
	}
	return string(b)
}

func truncate(s string) string {
	if len(s) > 40 {
		return s[:40] + "…"
	}
	return s
}
