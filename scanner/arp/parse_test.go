package arp

import (
	"io"
	"os"
	"strings"
	"testing"
)

func TestParseLinuxFixture(t *testing.T) {
	f, err := os.Open("testdata/linux.txt")
	if err != nil {
		t.Fatalf("фикстура: %v", err)
	}
	defer f.Close()
	entries, err := ParseLinux(f)
	if err != nil {
		t.Fatalf("ParseLinux: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf(" ParseLinux: получено %d записей, хочу 2: %+v", len(entries), entries)
	}
	if entries[0].IP.String() != "192.168.1.1" || entries[0].MAC != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("запись 0 = %+v, хочу 192.168.1.1 → aa:bb:cc:dd:ee:ff", entries[0])
	}
	if entries[1].IP.String() != "192.168.1.60" || entries[1].MAC != "aa:bb:cc:00:11:22" {
		t.Errorf("запись 1 = %+v, хочу 192.168.1.60 → aa:bb:cc:00:11:22", entries[1])
	}
}

func TestParseWindowsFixtures(t *testing.T) {
	tests := []struct {
		file string
	}{
		{file: "testdata/windows_en.txt"},
		{file: "testdata/windows_ru.txt"},
	}
	for _, tt := range tests {
		f, err := os.Open(tt.file)
		if err != nil {
			t.Fatalf("фикстура %s: %v", tt.file, err)
		}
		entries, err := ParseWindows(f)
		f.Close()
		if err != nil {
			t.Fatalf("%s: ParseWindows: %v", tt.file, err)
		}
		if len(entries) != 1 {
			t.Fatalf("%s: получено %d записей, хочу 1: %+v", tt.file, len(entries), entries)
		}
		if entries[0].IP.String() != "192.168.1.1" || entries[0].MAC != "aa:bb:cc:dd:ee:ff" {
			t.Errorf("%s: запись = %+v, хочу 192.168.1.1 → aa:bb:cc:dd:ee:ff", tt.file, entries[0])
		}
	}
}

func TestParseWindowsLanguageIndependent(t *testing.T) {
	read := func(name string) []Entry {
		f, err := os.Open(name)
		if err != nil {
			t.Fatalf("фикстура %s: %v", name, err)
		}
		defer f.Close()
		entries, err := ParseWindows(f)
		if err != nil {
			t.Fatalf("%s: ParseWindows: %v", name, err)
		}
		return entries
	}
	en := read("testdata/windows_en.txt")
	ru := read("testdata/windows_ru.txt")
	if len(en) != len(ru) {
		t.Fatalf("число записей различается: en=%d ru=%d", len(en), len(ru))
	}
	for i := range en {
		if en[i] != ru[i] {
			t.Errorf("запись %d различается: en=%+v ru=%+v", i, en[i], ru[i])
		}
	}
}

func TestParseWindowsMixedLanguage(t *testing.T) {
	// Слова на любом языке игнорируются: важны только «IPv4, пробелы, MAC».
	input := `Interface: 10.0.0.5 --- 0x7
интернет-адрес    физический адрес   тип
10.0.0.1          aC-cE-00-11-22-33  какой-то тип
мусор без адресов
10.0.0.2 not-a-mac динамический
`
	entries, err := ParseWindows(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseWindows: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("получено %d записей, хочу 1: %+v", len(entries), entries)
	}
	if entries[0].IP.String() != "10.0.0.1" || entries[0].MAC != "ac:ce:00:11:22:33" {
		t.Errorf("запись = %+v, хочу 10.0.0.1 → ac:ce:00:11:22:33", entries[0])
	}
}

func TestParseLinuxSkipsIncompleteAndMulticast(t *testing.T) {
	input := `IP address       HW type     Flags       HW address            Mask     Device
10.0.0.1         0x1         0x2         02:00:00:00:00:01     *        eth0
10.0.0.9         0x1         0x0         00:00:00:00:00:00     *        eth0
10.0.0.255       0x1         0x2         ff:ff:ff:ff:ff:ff     *        eth0
239.1.1.1        0x1         0x2         01:00:5e:01:01:01     *        eth0
224.0.0.22       0x1         0x2         02:00:00:00:00:02     *        eth0
10.0.0.3         0x1         0x2         zz:00:00:00:00:03     *        eth0
10.0.0.4         0x1         0x2         02:00:00:00:00:04     *        eth0
10.0.0.4         0x1         0x2         02:00:00:00:00:04     *        eth0
`
	entries, err := ParseLinux(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseLinux: %v", err)
	}
	// Остаются: .1, .4 (дубликат схлопнут).
	if len(entries) != 2 {
		t.Fatalf("получено %d записей, хочу 2: %+v", len(entries), entries)
	}
	if entries[0].IP.String() != "10.0.0.1" || entries[1].IP.String() != "10.0.0.4" {
		t.Errorf("записи = %+v, хочу 10.0.0.1 и 10.0.0.4", entries)
	}
}

func TestParseEmptyInput(t *testing.T) {
	for name, fn := range map[string]func(io.Reader) ([]Entry, error){
		"linux":   ParseLinux,
		"windows": ParseWindows,
	} {
		entries, err := fn(strings.NewReader(""))
		if err != nil {
			t.Errorf("%s: неожиданная ошибка: %v", name, err)
		}
		if len(entries) != 0 {
			t.Errorf("%s: на пустом входе получены записи: %+v", name, entries)
		}
	}
}
