package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
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

func runForTest(t *testing.T, args []string, getenv func(string) string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := runWith(args, getenv, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

// TestCLIMissingV3Env — без --snmp-v2c нужен SNMPv3: код 2, в
// сообщении — имена нехватнувших переменных, не значения.
func TestCLIMissingV3Env(t *testing.T) {
	code, _, stderr := runForTest(t, []string{
		"--subnets", "192.168.1.0/29", "--snmp-targets", "192.168.1.2",
	}, noEnv)
	if code != 2 {
		t.Fatalf("код = %d, хочу 2", code)
	}
	for _, name := range []string{"NETATLAS_SNMP_USER", "NETATLAS_SNMP_AUTH_PASS", "NETATLAS_SNMP_PRIV_PASS"} {
		if !strings.Contains(stderr, name) {
			t.Errorf("в сообщении нет имени переменной %s: %s", name, stderr)
		}
	}
}

// TestCLIMissingCommunity — v2c без сообщества: код 2 и имя переменной.
func TestCLIMissingCommunity(t *testing.T) {
	code, _, stderr := runForTest(t, []string{
		"--subnets", "192.168.1.0/29", "--snmp-targets", "192.168.1.2", "--snmp-v2c",
	}, noEnv)
	if code != 2 {
		t.Fatalf("код = %d, хочу 2", code)
	}
	if !strings.Contains(stderr, "NETATLAS_SNMP_COMMUNITY") {
		t.Errorf("в сообщении нет NETATLAS_SNMP_COMMUNITY: %s", stderr)
	}
}

// TestCLITargetOutsideScope — цель вне границ: код 2 до любых запросов.
func TestCLITargetOutsideScope(t *testing.T) {
	code, _, stderr := runForTest(t, []string{
		"--subnets", "192.168.1.0/29", "--snmp-targets", "10.9.9.9",
	}, secretEnv)
	if code != 2 {
		t.Fatalf("код = %d, хочу 2", code)
	}
	if !strings.Contains(stderr, "10.9.9.9") {
		t.Errorf("в сообщении нет отвергнутой цели: %s", stderr)
	}
}

// TestCLIInvalidTarget — не-IP в списке целей: код 2.
func TestCLIInvalidTarget(t *testing.T) {
	code, _, _ := runForTest(t, []string{
		"--subnets", "192.168.1.0/29", "--snmp-targets", "192.168.1.2,not-an-ip",
	}, secretEnv)
	if code != 2 {
		t.Fatalf("код = %d, хочу 2", code)
	}
}

// TestCLISecretsNotPrinted — с заведомо известными тестовыми значениями
// в переменных окружения ни JSON, ни ошибки не содержат их. Цель —
// 192.0.2.1 из TEST-NET-1 (RFC 5737): диапазон для документации,
// не маршрутизируется ни в сеть владельца, ни в интернет — соединение
// не отвечает, цель даёт запись с error, код 0.
func TestCLISecretsNotPrinted(t *testing.T) {
	code, stdout, stderr := runForTest(t, []string{
		"--subnets", "192.0.2.0/29", "--snmp-targets", "192.0.2.1", "--snmp-v2c",
	}, secretEnv)
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
}

// TestCLINoSNMPKeyByDefault — без --snmp-targets ключ snmp пустой [],
// код 0.
func TestCLINoSNMPKeyByDefault(t *testing.T) {
	code, stdout, _ := runForTest(t, []string{"--subnets", "192.168.1.0/29"}, noEnv)
	if code != 0 {
		t.Fatalf("код = %d, хочу 0", code)
	}
	if !strings.Contains(stdout, `"snmp": []`) {
		t.Errorf("ключ snmp должен быть пустым массивом: %s", stdout)
	}
}
