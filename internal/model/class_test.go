package model

import "testing"

func TestParseClass(t *testing.T) {
	tests := []struct {
		in      string
		want    Class
		wantErr bool
	}{
		{in: "managed", want: ClassManaged},
		{in: "known_no_agent", want: ClassKnownNoAgent},
		{in: "guest", want: ClassGuest},
		{in: "unknown", want: ClassUnknown},
		{in: "", wantErr: true},
		{in: "Guest", wantErr: true},
		{in: "other", wantErr: true},
	}
	for _, tt := range tests {
		got, err := ParseClass(tt.in)
		if tt.wantErr {
			if err == nil {
				t.Errorf("ParseClass(%q): ожидалась ошибка, получено %q", tt.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseClass(%q): неожиданная ошибка: %v", tt.in, err)
			continue
		}
		if got != tt.want {
			t.Errorf("ParseClass(%q) = %q, хочу %q", tt.in, got, tt.want)
		}
		if !got.Valid() {
			t.Errorf("ParseClass(%q): результат %q не проходит Valid()", tt.in, got)
		}
	}
}

func TestValidFalseForUnknown(t *testing.T) {
	for _, c := range []Class{"", "managed ", "MANAGED", "known-no-agent", "Guest", "other"} {
		if c.Valid() {
			t.Errorf("Class(%q).Valid() = true, хочу false", c)
		}
	}
}
