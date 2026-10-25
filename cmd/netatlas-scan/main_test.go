package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/ShkodnikAI/NetAtlas/internal/model"
	"github.com/ShkodnikAI/NetAtlas/scanner"
	"github.com/ShkodnikAI/NetAtlas/scanner/snmp"
)

func noEnv(key string) string { return "" }

func secretEnv(key string) string {
	switch key {
	case "NETATLAS_SNMP_COMMUNITY":
		return "v2c-secret-community-42"
	case "NETATLAS_SNMP_USER":
		return "v3-secret-user-42"
	case "NETATLAS_SNMP_AUTH_PASS":
		return "v3-secret-auth-42"
	case "NETATLAS_SNMP_PRIV_PASS":
		return "v3-secret-priv-42"
	}
	return ""
}

// runForTest исполняет runWith с подставной фабрикой walker'ов, так
// что тесты CLI не открывают SNMP-сокетов и не отправляют пакетов.
func runForTest(t *testing.T, args []string, getenv func(string) string, newWalker walkerFactory) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := runWith(args, getenv, &stdout, &stderr, newWalker)
	return code, stdout.String(), stderr.String()
}

// refuseFactory — фабрика для тестов без SNMP-целей: если CLI всё же
// вызвал её, значит пытался опросить цель там, где не должен.
func refuseFactory(t *testing.T) walkerFactory {
	t.Helper()
	return func(target netip.Addr, _ snmp.Auth) (snmp.Walker, error) {
		t.Errorf("фабрика walker'а вызвана для %v, хотя SNMP не запрашивался", target)
		return nil, errors.New("snmp: не ожидался")
	}
}

// testWalker — подставной Walker, обслуживаемый текстовыми фикстурами
// из scanner/snmp/testdata (тот же формат, что в пакетных тестах:
// «OID|kind|значение», kind: i — число, s — строка, x — hex-байты,
// o — OID). Get отдаёт точные OID, Walk — поддерево по префиксу;
// отсутствующие OID — KindNoSuch. Сеть не используется.
type testWalker struct {
	table      map[string]snmp.PDU
	order      []string
	getCalls   int
	walkCalls  int
	closeCalls int
}

// loadFixtureWalker читает фикстуры scanner/snmp/testdata.
func loadFixtureWalker(t *testing.T, files ...string) *testWalker {
	t.Helper()
	w := &testWalker{table: make(map[string]snmp.PDU)}
	for _, name := range files {
		data, err := os.ReadFile(filepath.Join("..", "..", "scanner", "snmp", "testdata", name))
		if err != nil {
			t.Fatalf("фикстура %s: %v", name, err)
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			parts := strings.SplitN(line, "|", 3)
			if len(parts) != 3 {
				t.Fatalf("фикстура %s: строка без трёх полей: %q", name, line)
			}
			oid, kind, val := parts[0], parts[1], parts[2]
			var pdu snmp.PDU
			switch kind {
			case "i":
				n, err := strconv.ParseInt(val, 10, 64)
				if err != nil {
					t.Fatalf("фикстура %s: %q: %v", name, line, err)
				}
				pdu = snmp.PDU{OID: oid, Kind: snmp.KindInt, Value: n}
			case "s":
				pdu = snmp.PDU{OID: oid, Kind: snmp.KindBytes, Value: []byte(val)}
			case "x":
				b, err := hex.DecodeString(val)
				if err != nil {
					t.Fatalf("фикстура %s: %q: %v", name, line, err)
				}
				pdu = snmp.PDU{OID: oid, Kind: snmp.KindBytes, Value: b}
			case "o":
				pdu = snmp.PDU{OID: oid, Kind: snmp.KindOID, Value: val}
			default:
				t.Fatalf("фикстура %s: неизвестный вид %q", name, kind)
			}
			if _, dup := w.table[oid]; !dup {
				w.order = append(w.order, oid)
			}
			w.table[oid] = pdu
		}
	}
	return w
}

func (w *testWalker) Get(_ context.Context, oids ...string) ([]snmp.PDU, error) {
	w.getCalls++
	out := make([]snmp.PDU, 0, len(oids))
	for _, oid := range oids {
		if p, ok := w.table[oid]; ok {
			out = append(out, p)
		} else {
			out = append(out, snmp.PDU{OID: oid, Kind: snmp.KindNoSuch, Value: nil})
		}
	}
	return out, nil
}

func (w *testWalker) Walk(_ context.Context, root string, fn func(snmp.PDU) error) error {
	w.walkCalls++
	for _, oid := range w.order {
		if !strings.HasPrefix(oid, root+".") {
			continue
		}
		if err := fn(w.table[oid]); err != nil {
			return err
		}
	}
	return nil
}

func (w *testWalker) Close() error {
	w.closeCalls++
	return nil
}

// fakeFactory — подставная фабрика walker'ов: считает вызовы и
// запоминает, какие цели и учётные данные до неё дошли. По err
// имитирует цель, которая не отвечает; по walker — успешную цель.
type fakeFactory struct {
	err     error
	walker  snmp.Walker
	targets []netip.Addr
	auths   []snmp.Auth
}

func (f *fakeFactory) new(target netip.Addr, a snmp.Auth) (snmp.Walker, error) {
	f.targets = append(f.targets, target)
	f.auths = append(f.auths, a)
	if f.err != nil {
		return nil, f.err
	}
	return f.walker, nil
}

// TestCLIMissingV3Env — без --snmp-v2c нужен SNMPv3: код 2, в
// сообщении — имена нехватнувших переменных, не значения; до фабрики
// walker'ов дело не доходит.
func TestCLIMissingV3Env(t *testing.T) {
	code, _, stderr := runForTest(t, []string{
		"--subnets", "192.168.1.0/29", "--snmp-targets", "192.168.1.2",
	}, noEnv, refuseFactory(t))
	if code != 2 {
		t.Fatalf("код = %d, хочу 2", code)
	}
	for _, name := range []string{"NETATLAS_SNMP_USER", "NETATLAS_SNMP_AUTH_PASS", "NETATLAS_SNMP_PRIV_PASS"} {
		if !strings.Contains(stderr, name) {
			t.Errorf("в сообщении нет имени переменной %s: %s", name, stderr)
		}
	}
}

// TestCLIMissingCommunity — v2c без сообщества: код 2 и имя
// переменной; до фабрики walker'ов дело не доходит.
func TestCLIMissingCommunity(t *testing.T) {
	code, _, stderr := runForTest(t, []string{
		"--subnets", "192.168.1.0/29", "--snmp-targets", "192.168.1.2", "--snmp-v2c",
	}, noEnv, refuseFactory(t))
	if code != 2 {
		t.Fatalf("код = %d, хочу 2", code)
	}
	if !strings.Contains(stderr, "NETATLAS_SNMP_COMMUNITY") {
		t.Errorf("в сообщении нет NETATLAS_SNMP_COMMUNITY: %s", stderr)
	}
}

// TestCLITargetOutsideScope — цель вне границ: код 2 до любых запросов
// и до создания walker'а.
func TestCLITargetOutsideScope(t *testing.T) {
	code, _, stderr := runForTest(t, []string{
		"--subnets", "192.168.1.0/29", "--snmp-targets", "10.9.9.9",
	}, secretEnv, refuseFactory(t))
	if code != 2 {
		t.Fatalf("код = %d, хочу 2", code)
	}
	if !strings.Contains(stderr, "10.9.9.9") {
		t.Errorf("в сообщении нет отвергнутой цели: %s", stderr)
	}
}

// TestCLIInvalidTarget — не-IP в списке целей: код 2, без walker'а.
func TestCLIInvalidTarget(t *testing.T) {
	code, _, _ := runForTest(t, []string{
		"--subnets", "192.168.1.0/29", "--snmp-targets", "192.168.1.2,not-an-ip",
	}, secretEnv, refuseFactory(t))
	if code != 2 {
		t.Fatalf("код = %d, хочу 2", code)
	}
}

// TestCLISecretsNotPrinted — с заведомо известными тестовыми значениями
// в переменных окружения ни JSON, ни ошибки не содержат их. Walker
// подменён фабрикой, имитирующей цель без ответа: сеть не используется,
// пакеты никуда не уходят. Цель 192.0.2.1 из TEST-NET-1 (RFC 5737)
// сохранена как маркер немаршрутизируемого адреса. Учётные данные
// доходят до фабрики (это проверяется), но не попадают в вывод.
func TestCLISecretsNotPrinted(t *testing.T) {
	ff := &fakeFactory{err: errors.New("snmp: система: request timeout (after 2 retries)")}
	code, stdout, stderr := runForTest(t, []string{
		"--subnets", "192.0.2.0/29", "--snmp-targets", "192.0.2.1", "--snmp-v2c",
	}, secretEnv, ff.new)
	if code != 0 {
		t.Fatalf("код = %d, хочу 0 (неответившая цель — запись с error): %s", code, stderr)
	}
	for _, secret := range []string{"v2c-secret-community-42", "v3-secret-user-42", "v3-secret-auth-42", "v3-secret-priv-42"} {
		if strings.Contains(stdout, secret) || strings.Contains(stderr, secret) {
			t.Errorf("учётные данные утекли (%q)", secret)
		}
	}
	var out scanOutput
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("JSON: %v\n%s", err, stdout)
	}
	if len(out.Snmp) != 1 || out.Snmp[0].Target.String() != "192.0.2.1" || out.Snmp[0].Error == "" {
		t.Fatalf("snmp-запись = %+v, хочу цель 192.0.2.1 с error", out.Snmp)
	}
	// фабрика вызвана один раз, с правильной целью и сообществом из env
	if len(ff.targets) != 1 || ff.targets[0].String() != "192.0.2.1" {
		t.Errorf("фабрика вызвана %d раз(а) для %v, хочу 1 вызов для 192.0.2.1", len(ff.targets), ff.targets)
	}
	if len(ff.auths) != 1 || ff.auths[0].Community != "v2c-secret-community-42" {
		t.Errorf("до фабрики не дошло сообщество из окружения: %+v", ff.auths)
	}
}

// TestCLISNMPFixtureData — успешный сбор по фикстурам
// scanner/snmp/testdata: код 0, без error, JSON содержит sys_name,
// sys_descr, порты, FDB и LLDP. Walker использован и закрыт ровно
// один раз — ресурс без утечек, сеть не тронута.
func TestCLISNMPFixtureData(t *testing.T) {
	w := loadFixtureWalker(t, "sys.txt", "ifname.txt", "qbridge.txt",
		"lldp_chassis_subtype.txt", "lldp_chassis_id.txt", "lldp_port_subtype.txt",
		"lldp_port_id.txt", "lldp_sysname.txt")
	ff := &fakeFactory{walker: w}
	code, stdout, stderr := runForTest(t, []string{
		"--subnets", "192.0.2.0/29", "--snmp-targets", "192.0.2.1", "--snmp-v2c",
	}, secretEnv, ff.new)
	if code != 0 {
		t.Fatalf("код = %d, хочу 0: %s", code, stderr)
	}
	if stderr != "" {
		t.Errorf("stderr не пуст: %s", stderr)
	}
	var out scanOutput
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("JSON: %v\n%s", err, stdout)
	}
	if len(out.Snmp) != 1 {
		t.Fatalf("записей snmp = %d, хочу 1", len(out.Snmp))
	}
	tr := out.Snmp[0]
	if tr.Target.String() != "192.0.2.1" {
		t.Errorf("target = %s, хочу 192.0.2.1", tr.Target)
	}
	if tr.Error != "" {
		t.Errorf("error = %q, хочу пусто", tr.Error)
	}
	if tr.SysName != "sw-core" || tr.SysDescr != "Cisco IOS Software, C2960" {
		t.Errorf("система = %q / %q", tr.SysName, tr.SysDescr)
	}
	if len(tr.Ports) != 3 {
		t.Errorf("портов = %d, хочу 3: %+v", len(tr.Ports), tr.Ports)
	}
	if len(tr.FDB) != 2 {
		t.Errorf("fdb = %d, хочу 2: %+v", len(tr.FDB), tr.FDB)
	}
	if len(tr.LLDP) != 2 {
		t.Errorf("lldp = %d, хочу 2: %+v", len(tr.LLDP), tr.LLDP)
	}
	// фабрика вызвана один раз с правильной целью
	if len(ff.targets) != 1 || ff.targets[0].String() != "192.0.2.1" {
		t.Errorf("фабрика вызвана %d раз(а) для %v, хочу 1 вызов для 192.0.2.1", len(ff.targets), ff.targets)
	}
	if w.getCalls == 0 || w.walkCalls == 0 {
		t.Errorf("walker не использован: get=%d walk=%d", w.getCalls, w.walkCalls)
	}
	if w.closeCalls != 1 {
		t.Errorf("walker закрыт %d раз(а), хочу 1", w.closeCalls)
	}
}

// TestCLISNMPFactoryCalledPerTarget — тест на сокет: при
// --snmp-targets CLI строит walker только через фабрику, по одному
// вызову на цель; настоящий NewGoWalker из тестов недостижим — ни
// один тест не передаёт realWalker. Цель без ответа не мешает
// обработке следующей: обе записи с error, код 0.
func TestCLISNMPFactoryCalledPerTarget(t *testing.T) {
	ff := &fakeFactory{err: errors.New("snmp: нет ответа (подставной walker)")}
	code, stdout, _ := runForTest(t, []string{
		"--subnets", "192.0.2.0/29", "--snmp-targets", "192.0.2.1,192.0.2.2", "--snmp-v2c",
	}, secretEnv, ff.new)
	if code != 0 {
		t.Fatalf("код = %d, хочу 0", code)
	}
	if len(ff.targets) != 2 || ff.targets[0].String() != "192.0.2.1" || ff.targets[1].String() != "192.0.2.2" {
		t.Fatalf("фабрика вызвана %d раз(а) для %v, хочу 2 вызова — по цели на каждую", len(ff.targets), ff.targets)
	}
	var out scanOutput
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("JSON: %v\n%s", err, stdout)
	}
	for i, want := range []string{"192.0.2.1", "192.0.2.2"} {
		if len(out.Snmp) <= i || out.Snmp[i].Target.String() != want || out.Snmp[i].Error == "" {
			t.Errorf("запись %d = %+v, хочу цель %s с error", i, out.Snmp[i], want)
		}
	}
}

// TestCLINoSNMPKeyByDefault — без --snmp-targets ключ snmp пустой [],
// код 0; до фабрики walker'ов дело не доходит.
func TestCLINoSNMPKeyByDefault(t *testing.T) {
	code, stdout, _ := runForTest(t, []string{"--subnets", "192.168.1.0/29"}, noEnv, refuseFactory(t))
	if code != 0 {
		t.Fatalf("код = %d, хочу 0", code)
	}
	if !strings.Contains(stdout, `"snmp": []`) {
		t.Errorf("ключ snmp должен быть пустым массивом: %s", stdout)
	}
}

// --- NR-016: DHCP-аренды ---

func TestCLILeasesFlagsTogether(t *testing.T) {
	// --leases без --leases-format — код 2.
	code, _, stderr := runForTest(t, []string{
		"--subnets", "192.0.2.0/24",
		"--leases", "testdata/leases_cli_isc.txt",
	}, noEnv, refuseFactory(t))
	if code != 2 {
		t.Errorf("--leases без --leases-format: код = %d, ждём 2; stderr: %s", code, stderr)
	}
	// --leases-format без --leases — код 2.
	code, _, stderr = runForTest(t, []string{
		"--subnets", "192.0.2.0/24",
		"--leases-format", "isc",
	}, noEnv, refuseFactory(t))
	if code != 2 {
		t.Errorf("--leases-format без --leases: код = %d, ждём 2; stderr: %s", code, stderr)
	}
}

func TestCLILeasesBadFormat(t *testing.T) {
	code, _, stderr := runForTest(t, []string{
		"--subnets", "192.0.2.0/24",
		"--leases", "testdata/leases_cli_isc.txt",
		"--leases-format", "xml",
	}, noEnv, refuseFactory(t))
	if code != 2 {
		t.Errorf("формат xml: код = %d, ждём 2; stderr: %s", code, stderr)
	}
}

func TestCLILeasesNoSuchFile(t *testing.T) {
	code, _, stderr := runForTest(t, []string{
		"--subnets", "192.0.2.0/24",
		"--leases", "testdata/no_such_leases.txt",
		"--leases-format", "isc",
	}, noEnv, refuseFactory(t))
	if code != 1 {
		t.Errorf("несуществующий файл: код = %d, ждём 1; stderr: %s", code, stderr)
	}
}

func TestCLILeasesMerged(t *testing.T) {
	cases := []struct {
		name, file, format, mac, vendor, ssid string
	}{
		{"isc", "testdata/leases_cli_isc.txt", "isc", "00:00:0c:11:22:33", "Cisco Systems, Inc", ""},
		{"csv", "testdata/leases_cli_csv.csv", "csv", "aa:bb:cc:dd:ee:f0", "", "HomeWiFi"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, stdout, stderr := runForTest(t, []string{
				"--subnets", "192.0.2.0/24",
				"--leases", tc.file,
				"--leases-format", tc.format,
			}, noEnv, refuseFactory(t))
			if code != 0 {
				t.Fatalf("код = %d, ждём 0; stderr: %s", code, stderr)
			}
			if !strings.Contains(stderr, "аренды: получено 1, пропущено 0") {
				t.Errorf("stderr без счётчика аренд: %q", stderr)
			}
			var out struct {
				scanner.Result
				Snmp []snmp.TargetResult `json:"snmp"`
			}
			if err := json.Unmarshal([]byte(stdout), &out); err != nil {
				t.Fatalf("JSON: %v\nвывод: %s", err, stdout)
			}
			var found *model.Device
			for i := range out.Devices {
				if out.Devices[i].ID == tc.mac {
					found = &out.Devices[i]
					break
				}
			}
			if found == nil {
				t.Fatalf("устройство %s не найдено в выводе; устройства: %+v", tc.mac, out.Devices)
			}
			if found.Vendor != tc.vendor {
				t.Errorf("vendor = %q, ждём %q", found.Vendor, tc.vendor)
			}
			if found.SSID != tc.ssid {
				t.Errorf("ssid = %q, ждём %q", found.SSID, tc.ssid)
			}
			hasDHCPName, hasDHCPObs := false, false
			for _, n := range found.Names {
				if n.Source == model.NameSourceDHCP {
					hasDHCPName = true
				}
			}
			for _, o := range found.Observations {
				if o.Source == "dhcp" {
					hasDHCPObs = true
				}
			}
			if !hasDHCPName {
				t.Errorf("нет имени с источником dhcp: %+v", found.Names)
			}
			if !hasDHCPObs {
				t.Errorf("нет наблюдения dhcp: %+v", found.Observations)
			}
		})
	}
}

// TestCLIVersion — флаг --version (NR-027): печатает строку версии
// без подсетей и окружения, код 0, фабрика walker'ов не вызывается.
func TestCLIVersion(t *testing.T) {
	called := false
	factory := func(netip.Addr, snmp.Auth) (snmp.Walker, error) {
		called = true
		return nil, nil
	}
	code, stdout, stderr := runForTest(t, []string{"--version"}, noEnv, factory)
	if code != 0 {
		t.Fatalf("код = %d, хочу 0 (stderr: %s)", code, stderr)
	}
	if called {
		t.Fatal("фабрика walker'ов вызвана при --version")
	}
	if !strings.Contains(stdout, "netatlas ") {
		t.Fatalf("в stdout нет версии: %q", stdout)
	}
}
