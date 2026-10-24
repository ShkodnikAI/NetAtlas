// Разбор вывода проверок на фикстурах: нормальный случай, русская
// локаль с CRLF, недоступные командлеты (пустой вывод), мусорный
// вывод. Ключевое правило: неизвестное состояние — unknown, а не
// «безопасно».
package checks

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func fixture(t *testing.T, name string) json.RawMessage {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("фикстура %s: %v", name, err)
	}
	return json.RawMessage(raw)
}

var now = time.Now()

func contextErr() error { return errors.New("checks: powershell smbv1: exit status 1") }

func TestParseSMBv1(t *testing.T) {
	cases := []struct {
		name   string
		raw    json.RawMessage
		status string
	}{
		{"включён", fixture(t, "smbv1_on.json"), StatusFail},
		{"отключён", fixture(t, "smbv1_off.json"), StatusPass},
		{"crlf локаль", fixture(t, "smbv1_crlf.json"), StatusFail},
		{"json-литерал", fixture(t, "smbv1_bool.json"), StatusFail},
		{"пустой вывод", nil, StatusUnknown},
		{"null", json.RawMessage("null"), StatusUnknown},
		{"мусор", json.RawMessage(`{"enabled":"кто его знает"}`), StatusUnknown},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res, err := parseSMBv1(c.raw)
			if err != nil {
				t.Fatalf("неожиданная ошибка: %v", err)
			}
			if res.Status != c.status {
				t.Fatalf("статус %q, ждём %q (detail: %s)", res.Status, c.status, res.Detail)
			}
			if res.ID != CheckSMBv1 {
				t.Fatalf("id %q", res.ID)
			}
		})
	}
	// Битый JSON: парсер возвращает ошибку, каркас (Run) переводит
	// её в unknown — «не безопасно».
	if _, err := parseSMBv1(json.RawMessage(`{"enabled":`)); err == nil {
		t.Fatal("битый JSON должен давать ошибку разбора (каркас переведёт её в unknown)")
	}
}

func TestParseBitLocker(t *testing.T) {
	res, err := parseBitLocker(fixture(t, "bitlocker_ru.json"))
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != StatusFail {
		t.Fatalf("том D: без защиты — должен быть fail, получен %q", res.Status)
	}
	if res.Detail != "тома без шифрования: D:" {
		t.Fatalf("detail: %q", res.Detail)
	}

	res, err = parseBitLocker(fixture(t, "bitlocker_all_on.json"))
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != StatusPass {
		t.Fatalf("все тома защищены — pass, получен %q", res.Status)
	}

	res, err = parseBitLocker(fixture(t, "bitlocker_unknown.json"))
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != StatusUnknown {
		t.Fatalf("Unknown — не «безопасно», ждём unknown, получен %q", res.Status)
	}

	res, err = parseBitLocker(nil)
	if err != nil || res.Status != StatusUnknown {
		t.Fatalf("пустой вывод: unknown, получен %q (err %v)", res.Status, err)
	}

	res, err = parseBitLocker(json.RawMessage(`{"volumes":[]}`))
	if err != nil || res.Status != StatusUnknown {
		t.Fatalf("пустой список томов: unknown, получен %q", res.Status)
	}
}

func TestParseRDPNLA(t *testing.T) {
	res, err := parseRDPNLA(fixture(t, "rdp_nla_vulnerable.json"))
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != StatusFail {
		t.Fatalf("RDP без NLA — fail, получен %q", res.Status)
	}
	res, err = parseRDPNLA(fixture(t, "rdp_nla_safe.json"))
	if err != nil || res.Status != StatusPass {
		t.Fatalf("RDP с NLA — pass, получен %q", res.Status)
	}
	res, err = parseRDPNLA(fixture(t, "rdp_nla_disabled.json"))
	if err != nil || res.Status != StatusPass {
		t.Fatalf("RDP выключен — pass, получен %q", res.Status)
	}
	// RDP включён, состояние NLA неизвестно — не «безопасно».
	res, err = parseRDPNLA(json.RawMessage(`{"rdpEnabled":"1"}`))
	if err != nil || res.Status != StatusUnknown {
		t.Fatalf("NLA не определено — unknown, получен %q", res.Status)
	}
}

func TestParseFirewall(t *testing.T) {
	res, err := parseFirewall(fixture(t, "firewall_off.json"))
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != StatusFail || res.Detail != "профиль выключен: Private" {
		t.Fatalf("fail с профилем Private, получен %q (%s)", res.Status, res.Detail)
	}
	res, err = parseFirewall(fixture(t, "firewall_ok.json"))
	if err != nil || res.Status != StatusPass {
		t.Fatalf("все профили включены — pass, получен %q", res.Status)
	}
	res, err = parseFirewall(fixture(t, "firewall_garbage.json"))
	if err != nil || res.Status != StatusUnknown {
		t.Fatalf("мусорное значение — unknown, получен %q", res.Status)
	}
	res, err = parseFirewall(nil)
	if err != nil || res.Status != StatusUnknown {
		t.Fatalf("пустой вывод — unknown, получен %q", res.Status)
	}
}

func TestParsePorts(t *testing.T) {
	res, err := parsePorts(fixture(t, "ports_mixed.json"))
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != StatusPass {
		t.Fatalf("список портов — данные без суждения, получен %q", res.Status)
	}
	var data struct {
		Ports []PortEntry `json:"ports"`
	}
	if err := json.Unmarshal(res.Data, &data); err != nil {
		t.Fatalf("data: %v", err)
	}
	if len(data.Ports) != 4 {
		t.Fatalf("портов: %d, ждём 4", len(data.Ports))
	}
	// Детерминированный порядок (лексикографический по адресу):
	// 135/0.0.0.0, 135/127.0.0.1, 445/::, 3389/0.0.0.0.
	order := []int{135, 135, 445, 3389}
	addrs := []string{"0.0.0.0", "127.0.0.1", "::", "0.0.0.0"}
	for i, p := range data.Ports {
		if p.LocalPort != order[i] || p.LocalAddress != addrs[i] {
			t.Fatalf("порядок нарушен в позиции %d: %+v", i, p)
		}
	}
	// Пустой список — рабочее состояние (нет слушающих портов).
	res, err = parsePorts(fixture(t, "ports_empty.json"))
	if err != nil || res.Status != StatusPass || res.Data != nil {
		t.Fatalf("пустой список: pass без данных, получен %q", res.Status)
	}
	res, err = parsePorts(nil)
	if err != nil || res.Status != StatusUnknown {
		t.Fatalf("пустой вывод сценария — unknown, получен %q", res.Status)
	}
}

func TestParseDefender(t *testing.T) {
	res, err := parseDefender(fixture(t, "defender_off.json"))
	if err != nil || res.Status != StatusFail {
		t.Fatalf("реальная защита отключена — fail, получен %q", res.Status)
	}
	res, err = parseDefender(fixture(t, "defender_ok.json"))
	if err != nil || res.Status != StatusPass {
		t.Fatalf("защита включена — pass, получен %q", res.Status)
	}
	// Антивирус выключен целиком: не «безопасно» — суждение за владельцем.
	res, err = parseDefender(fixture(t, "defender_av_off.json"))
	if err != nil || res.Status != StatusUnknown {
		t.Fatalf("антивирус выключен — unknown, получен %q", res.Status)
	}
	res, err = parseDefender(nil)
	if err != nil || res.Status != StatusUnknown {
		t.Fatalf("командлета нет — unknown, получен %q", res.Status)
	}
}

func TestBuildReportErrorsAreUnknown(t *testing.T) {
	// Проверка, вернувшая ошибку, попадает в отчёт как unknown
	// с причиной в detail и не роняет остальные проверки.
	ok := &fakeCheck{name: CheckFirewall, res: Result{ID: CheckFirewall, Status: StatusPass}}
	bad := &fakeCheck{name: CheckSMBv1, err: contextErr()}
	badStatus := &fakeCheck{name: CheckBitLocker, res: Result{ID: CheckBitLocker, Status: "safe"}}
	rep := BuildReport(t.Context(), "host", []Checker{ok, bad, badStatus}, now)
	if len(rep.Results) != 3 {
		t.Fatalf("результатов: %d", len(rep.Results))
	}
	if rep.Results[0].Status != StatusPass {
		t.Fatalf("рабочая проверка пострадала: %+v", rep.Results[0])
	}
	if rep.Results[1].Status != StatusUnknown {
		t.Fatalf("ошибка проверки — unknown, получен %q", rep.Results[1].Status)
	}
	if rep.Results[1].Detail == "" {
		t.Fatal("причина ошибки должна остаться в detail")
	}
	if rep.Results[2].Status != StatusUnknown {
		t.Fatalf("недопустимый статус — unknown, получен %q", rep.Results[2].Status)
	}
	if rep.SecuritySchemaVersion != SchemaVersion {
		t.Fatalf("версия схемы: %d", rep.SecuritySchemaVersion)
	}
}

// fakeCheck — подменяемая проверка для тестов каркаса.
type fakeCheck struct {
	name string
	res  Result
	err  error
}

func (f *fakeCheck) Name() string { return f.name }

func (f *fakeCheck) Run(_ context.Context) (Result, error) { return f.res, f.err }
