package main

import (
	"strings"
	"testing"
)

func getenv(mapEnv map[string]string) func(string) string {
	return func(k string) string { return mapEnv[k] }
}

const goodToken = "0123456789abcdef01234567" // 24 символа

func TestParseConfigOK(t *testing.T) {
	cfg, err := parseConfig([]string{"--db", "/tmp/x.db", "--subnets", "10.0.0.0/24"},
		getenv(map[string]string{"NETATLAS_TOKEN": goodToken}))
	if err != nil {
		t.Fatalf("конфигурация: %v", err)
	}
	if cfg.listen != "127.0.0.1:8484" {
		t.Errorf("listen = %q, хочу 127.0.0.1:8484 по умолчанию", cfg.listen)
	}
	if cfg.scope == nil {
		t.Fatalf("scope не построен")
	}
}

func TestParseConfigRejectsShortToken(t *testing.T) {
	_, err := parseConfig([]string{"--db", "/tmp/x.db", "--subnets", "10.0.0.0/24"},
		getenv(map[string]string{"NETATLAS_TOKEN": "короткий"}))
	if err == nil || !strings.Contains(err.Error(), "NETATLAS_TOKEN") {
		t.Fatalf("ошибка = %v, хочу упоминание NETATLAS_TOKEN", err)
	}
	if strings.Contains(err.Error(), "короткий") && !strings.Contains(err.Error(), "короче") {
		t.Fatalf("ошибка выводит значение переменной: %v", err)
	}
}

func TestParseConfigRejectsMissingToken(t *testing.T) {
	_, err := parseConfig([]string{"--db", "/tmp/x.db", "--subnets", "10.0.0.0/24"}, getenv(nil))
	if err == nil || !strings.Contains(err.Error(), "NETATLAS_TOKEN") {
		t.Fatalf("ошибка = %v, хочу упоминание NETATLAS_TOKEN", err)
	}
}

func TestParseConfigRejectsNonLocalListen(t *testing.T) {
	for _, listen := range []string{"0.0.0.0:8484", "192.168.1.5:8484", ":8484"} {
		_, err := parseConfig([]string{"--db", "/tmp/x.db", "--subnets", "10.0.0.0/24", "--listen", listen},
			getenv(map[string]string{"NETATLAS_TOKEN": goodToken}))
		if err == nil || !strings.Contains(err.Error(), "--allow-remote") {
			t.Fatalf("listen %q: ошибка = %v, хочу требование --allow-remote", listen, err)
		}
	}
	// С явным --allow-remote тот же адрес допустим.
	if _, err := parseConfig([]string{"--db", "/tmp/x.db", "--subnets", "10.0.0.0/24",
		"--listen", "192.168.1.5:8484", "--allow-remote"},
		getenv(map[string]string{"NETATLAS_TOKEN": goodToken})); err != nil {
		t.Fatalf("с --allow-remote: %v", err)
	}
}

func TestParseConfigRejectsMissingSubnets(t *testing.T) {
	_, err := parseConfig([]string{"--db", "/tmp/x.db"},
		getenv(map[string]string{"NETATLAS_TOKEN": goodToken}))
	if err == nil || !strings.Contains(err.Error(), "--subnets") {
		t.Fatalf("ошибка = %v, хочу требование --subnets", err)
	}
}

func TestParseConfigRejectsBadSubnet(t *testing.T) {
	_, err := parseConfig([]string{"--db", "/tmp/x.db", "--subnets", "не-cidr"},
		getenv(map[string]string{"NETATLAS_TOKEN": goodToken}))
	if err == nil {
		t.Fatalf("неверная подсеть прошла")
	}
}

// Агентские слушатели выключены по умолчанию: без флагов конфиг не
// содержит адресов, run() не открывает порты агентов.
func TestParseConfigAgentsOffByDefault(t *testing.T) {
	cfg, err := parseConfig([]string{"--db", "/tmp/x.db", "--subnets", "10.0.0.0/24"},
		getenv(map[string]string{"NETATLAS_TOKEN": goodToken}))
	if err != nil {
		t.Fatalf("конфигурация: %v", err)
	}
	if cfg.agentListen != "" || cfg.agentEnrollListen != "" {
		t.Fatalf("агентские слушатели включены по умолчанию: %q / %q", cfg.agentListen, cfg.agentEnrollListen)
	}
}

// Порт агентов не может совпадать с портом владельца.
func TestParseConfigRejectsAgentPortClash(t *testing.T) {
	env := getenv(map[string]string{
		"NETATLAS_TOKEN":  goodToken,
		"NETATLAS_KEYDIR": "/keys",
	})
	for _, args := range [][]string{
		{"--db", "/x", "--subnets", "10.0.0.0/24", "--listen", "127.0.0.1:8484",
			"--agent-listen", "127.0.0.1:8484"},
		{"--db", "/x", "--subnets", "10.0.0.0/24", "--listen", "127.0.0.1:8484",
			"--agent-listen", "127.0.0.1:9000", "--agent-enroll-listen", "127.0.0.1:8484"},
	} {
		if _, err := parseConfig(args, env); err == nil || !strings.Contains(err.Error(), "не смешивается") {
			t.Fatalf("args %v: ошибка = %v, хочу запрет совпадения портов", args, err)
		}
	}
}

// Слушатель регистрации без mTLS-слушателя — ошибка конфигурации,
// как и совпадение двух агентских адресов.
func TestParseConfigRejectsBrokenAgentSetup(t *testing.T) {
	env := getenv(map[string]string{
		"NETATLAS_TOKEN":  goodToken,
		"NETATLAS_KEYDIR": "/keys",
	})
	if _, err := parseConfig([]string{"--db", "/x", "--subnets", "10.0.0.0/24",
		"--agent-enroll-listen", "127.0.0.1:9001"}, env); err == nil ||
		!strings.Contains(err.Error(), "--agent-listen") {
		t.Fatalf("enroll без mTLS: %v", err)
	}
	if _, err := parseConfig([]string{"--db", "/x", "--subnets", "10.0.0.0/24",
		"--agent-listen", "127.0.0.1:9000", "--agent-enroll-listen", "127.0.0.1:9000"}, env); err == nil ||
		!strings.Contains(err.Error(), "совпадают") {
		t.Fatalf("одинаковые агентские адреса: %v", err)
	}
}

// Агентские адреса следуют той же локальной политике, что и порт
// владельца; без NETATLAS_KEYDIR сервер с агентами не стартует.
func TestParseConfigAgentAddressPolicy(t *testing.T) {
	tokenEnv := getenv(map[string]string{"NETATLAS_TOKEN": goodToken})
	if _, err := parseConfig([]string{"--db", "/x", "--subnets", "10.0.0.0/24",
		"--agent-listen", "0.0.0.0:9000"}, tokenEnv); err == nil || !strings.Contains(err.Error(), "--allow-remote") {
		t.Fatalf("нелокальный --agent-listen без --allow-remote: %v", err)
	}
	env := getenv(map[string]string{
		"NETATLAS_TOKEN":  goodToken,
		"NETATLAS_KEYDIR": "/keys",
	})
	if _, err := parseConfig([]string{"--db", "/x", "--subnets", "10.0.0.0/24",
		"--agent-listen", "127.0.0.1:9000", "--agent-enroll-listen", "127.0.0.1:9001"}, env); err != nil {
		t.Fatalf("корректная настройка агентов: %v", err)
	}
	if _, err := parseConfig([]string{"--db", "/x", "--subnets", "10.0.0.0/24",
		"--agent-listen", "127.0.0.1:9000"}, tokenEnv); err == nil || !strings.Contains(err.Error(), "NETATLAS_KEYDIR") {
		t.Fatalf("без каталога ключей: %v", err)
	}
}

// Диспетчеризация (NR-011): выключена по умолчанию; с флагом нужны
// ключи и слушатель агентов; произвольные скрипты — отдельный флаг.
func TestParseConfigDispatchFlags(t *testing.T) {
	env := func(k string) string {
		if k == "NETATLAS_TOKEN" {
			return "tok-" + strings.Repeat("e", 30)
		}
		return "" // ключей и SNMP-переменных нет
	}

	cfg, err := parseConfig([]string{"--db", "/x", "--subnets", "10.0.0.0/24"}, env)
	if err != nil {
		t.Fatalf("без флагов: %v", err)
	}
	if cfg.enableDispatch || cfg.allowCustomScripts {
		t.Fatal("диспетчеризация должна быть выключена по умолчанию")
	}

	if _, err := parseConfig([]string{"--db", "/x", "--subnets", "10.0.0.0/24", "--enable-dispatch"}, env); err == nil ||
		!strings.Contains(err.Error(), "NETATLAS_KEYDIR") {
		t.Fatalf("dispatch без ключей: %v", err)
	}

	if _, err := parseConfig([]string{"--db", "/x", "--subnets", "10.0.0.0/24",
		"--enable-dispatch"}, func(k string) string {
		if k == "NETATLAS_TOKEN" {
			return "tok-" + strings.Repeat("e", 30)
		}
		return "/tmp/keys"
	}); err == nil || !strings.Contains(err.Error(), "--agent-listen") {
		t.Fatalf("dispatch без слушателя агентов: %v", err)
	}

	cfg, err = parseConfig([]string{"--db", "/x", "--subnets", "10.0.0.0/24",
		"--enable-dispatch", "--allow-custom-scripts", "--agent-listen", "127.0.0.1:9001"}, func(k string) string {
		if k == "NETATLAS_TOKEN" {
			return "tok-" + strings.Repeat("e", 30)
		}
		return "/tmp/keys"
	})
	if err != nil {
		t.Fatalf("полная конфигурация: %v", err)
	}
	if !cfg.enableDispatch || !cfg.allowCustomScripts {
		t.Fatal("флаги не прочитаны")
	}
}
