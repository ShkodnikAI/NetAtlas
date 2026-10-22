package model

import "testing"

func TestNormalizeMAC(t *testing.T) {
	tests := []struct {
		in      string
		want    string
		wantErr bool
	}{
		// Допустимые формы.
		{in: "AA:BB:CC:DD:EE:FF", want: "aa:bb:cc:dd:ee:ff"},
		{in: "aa-bb-cc-dd-ee-ff", want: "aa:bb:cc:dd:ee:ff"},
		{in: "AABB.CCDD.EEFF", want: "aa:bb:cc:dd:ee:ff"},
		{in: "Aa:Bb:Cc:Dd:Ee:Ff", want: "aa:bb:cc:dd:ee:ff"},
		{in: "00:11:22:33:44:55", want: "00:11:22:33:44:55"},
		{in: "02-00-00-00-00-01", want: "02:00:00:00:00:01"},
		// Неверная длина и разбивка.
		{in: "aa:bb:cc:dd:ee", wantErr: true},
		{in: "aa:bb:cc:dd:ee:ff:00", wantErr: true},
		{in: "aabb.ccdd.ee", wantErr: true},
		{in: "aa:bb-cc:dd-ee:ff", wantErr: true},
		{in: "aabbccddeeff", wantErr: true},
		{in: "", wantErr: true},
		// Нешестнадцатеричные символы.
		{in: "aa:bb:cc:dd:ee:zz", wantErr: true},
		{in: "aa:bb:cc:dd:ee:fg", wantErr: true},
		// Нулевой адрес.
		{in: "00:00:00:00:00:00", wantErr: true},
		{in: "00-00-00-00-00-00", wantErr: true},
		// Широковещательный.
		{in: "ff:ff:ff:ff:ff:ff", wantErr: true},
		{in: "FF-FF-FF-FF-FF-FF", wantErr: true},
		// Групповые (младший бит первого октета равен 1).
		{in: "01:00:5e:00:00:16", wantErr: true},
		{in: "01-00-5e-00-00-16", wantErr: true},
		{in: "03:00:00:00:00:01", wantErr: true},
	}
	for _, tt := range tests {
		got, err := NormalizeMAC(tt.in)
		if tt.wantErr {
			if err == nil {
				t.Errorf("NormalizeMAC(%q): ожидалась ошибка, получено %q", tt.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("NormalizeMAC(%q): неожиданная ошибка: %v", tt.in, err)
			continue
		}
		if got != tt.want {
			t.Errorf("NormalizeMAC(%q) = %q, хочу %q", tt.in, got, tt.want)
		}
	}
}
