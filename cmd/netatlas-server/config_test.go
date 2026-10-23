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
