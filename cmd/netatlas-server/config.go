package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/ShkodnikAI/NetAtlas/scanner"
	"github.com/ShkodnikAI/NetAtlas/scanner/snmp"
)

// config — параметры запуска сервера.
type config struct {
	dbPath      string
	listen      string
	allowRemote bool
	allowLarge  bool
	subnetList  []string
	scope       *scanner.Scope
	token       string

	// Агентский API (NR-024): оба адреса пустые по умолчанию —
	// сервер без явных флагов агентов не принимает.
	agentListen       string
	agentEnrollListen string
	keyDir            string

	// Правила (NR-009): пусто — встроенные.
	rulesDir string

	// Качество сети (NR-008): цели SNMP пустые — задача выключена.
	snmpTargets string
	snmpList    []netip.Addr
}

// errUsage — ошибки конфигурации: завершение с кодом 2.
var errUsage = errors.New("неверные параметры")

// parseConfig разбирает флаги и окружение. Токен читается из
// переменной NETATLAS_TOKEN; в текстах ошибок только имена переменных
// и флагов, значения не печатаются никогда.
func parseConfig(args []string, getenv func(string) string) (config, error) {
	fs := flag.NewFlagSet("netatlas-server", flag.ContinueOnError)
	fs.SetOutput(nil)
	var cidrs string
	cfg := config{}
	fs.StringVar(&cfg.dbPath, "db", "", "путь базы SQLite")
	fs.StringVar(&cfg.listen, "listen", "127.0.0.1:8484", "адрес прослушивания")
	fs.BoolVar(&cfg.allowRemote, "allow-remote", false, "разрешить нелокальный адрес")
	fs.StringVar(&cidrs, "subnets", "", "подсети проверки, через запятую")
	fs.BoolVar(&cfg.allowLarge, "allow-large", false, "разрешить большие подсети")
	fs.StringVar(&cfg.agentListen, "agent-listen", "",
		"адрес mTLS-слушателя агентов (по умолчанию выключен)")
	fs.StringVar(&cfg.agentEnrollListen, "agent-enroll-listen", "",
		"адрес слушателя регистрации агентов (по умолчанию выключен)")
	fs.StringVar(&cfg.rulesDir, "rules-dir", "",
		"каталог правил (по умолчанию — встроенные rules/data)")
	fs.StringVar(&cfg.snmpTargets, "snmp-targets", "",
		"цели SNMP-опроса портов, через запятую (по умолчанию выключено)")
	if err := fs.Parse(args); err != nil {
		return config{}, fmt.Errorf("%w: %v", errUsage, err)
	}
	if fs.NArg() > 0 {
		return config{}, fmt.Errorf("%w: лишние аргументы %q", errUsage, fs.Args())
	}
	if cfg.dbPath == "" {
		return config{}, fmt.Errorf("%w: нужен --db", errUsage)
	}
	if err := checkListen(cfg.listen, cfg.allowRemote); err != nil {
		return config{}, err
	}
	var list []string
	for _, c := range strings.Split(cidrs, ",") {
		if c = strings.TrimSpace(c); c != "" {
			list = append(list, c)
		}
	}
	cfg.subnetList = list
	scope, err := scanner.NewScope(list, cfg.allowLarge)
	if err != nil {
		return config{}, fmt.Errorf("%w: --subnets: %v", errUsage, err)
	}
	cfg.scope = scope

	// Цели SNMP: только внутри подсетей (проверка в metrics.NewTask).
	for _, c := range strings.Split(cfg.snmpTargets, ",") {
		if c = strings.TrimSpace(c); c == "" {
			continue
		}
		addr, err := netip.ParseAddr(c)
		if err != nil {
			return config{}, fmt.Errorf("%w: --snmp-targets: %q не адрес", errUsage, c)
		}
		cfg.snmpList = append(cfg.snmpList, addr)
	}

	// Каталог ключей PKI: только окружение, как и токен.
	cfg.keyDir = getenv("NETATLAS_KEYDIR")

	// Агентские слушатели: адреса проверяются как порт владельца
	// (локальные по умолчанию), совпадения портов запрещены, для
	// работы нужен каталог ключей.
	agentsOn := cfg.agentListen != "" || cfg.agentEnrollListen != ""
	if agentsOn {
		if cfg.agentListen == "" {
			return config{}, fmt.Errorf("%w: --agent-enroll-listen без --agent-listen: некуда принимать агентов", errUsage)
		}
		if err := checkListen(cfg.agentListen, cfg.allowRemote); err != nil {
			return config{}, fmt.Errorf("--agent-listen: %w", err)
		}
		if cfg.agentEnrollListen != "" {
			if err := checkListen(cfg.agentEnrollListen, cfg.allowRemote); err != nil {
				return config{}, fmt.Errorf("--agent-enroll-listen: %w", err)
			}
		}
		if cfg.agentListen == cfg.agentEnrollListen {
			return config{}, fmt.Errorf("%w: --agent-listen и --agent-enroll-listen совпадают", errUsage)
		}
		if cfg.agentListen == cfg.listen || cfg.agentEnrollListen == cfg.listen {
			return config{}, fmt.Errorf("%w: порт агентов не смешивается с портом владельца", errUsage)
		}
		if cfg.keyDir == "" {
			return config{}, fmt.Errorf("%w: переменная окружения NETATLAS_KEYDIR не задана", errUsage)
		}
	}

	cfg.token = getenv("NETATLAS_TOKEN")
	if cfg.token == "" {
		return config{}, fmt.Errorf("%w: переменная окружения NETATLAS_TOKEN не задана", errUsage)
	}
	if len(cfg.token) < 24 {
		return config{}, fmt.Errorf("%w: NETATLAS_TOKEN короче 24 символов", errUsage)
	}
	return cfg, nil
}

// snmpServerAuth — учётные данные SNMP из переменных окружения:
// NETATLAS_SNMP_COMMUNITY задан — SNMPv2c, иначе v3 authPriv.
// Значения не печатаются никогда; второй результат — готовность.
func snmpServerAuth(getenv func(string) string) (snmp.Auth, bool) {
	if c := getenv("NETATLAS_SNMP_COMMUNITY"); c != "" {
		return snmp.Auth{V2C: true, Community: c}, true
	}
	user, authPass, privPass := getenv("NETATLAS_SNMP_USER"), getenv("NETATLAS_SNMP_AUTH_PASS"), getenv("NETATLAS_SNMP_PRIV_PASS")
	if user == "" || authPass == "" || privPass == "" {
		return snmp.Auth{}, false
	}
	return snmp.Auth{User: user, AuthPass: authPass, PrivPass: privPass}, true
}

// checkListen — нелокальный адрес только с явным --allow-remote.
func checkListen(listen string, allowRemote bool) error {
	if allowRemote {
		return nil
	}
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return fmt.Errorf("%w: --listen %q: %v", errUsage, listen, err)
	}
	switch host {
	case "127.0.0.1", "::1", "localhost":
		return nil
	}
	if a, err := netip.ParseAddr(host); err == nil && a.IsLoopback() {
		return nil
	}
	return fmt.Errorf("%w: --listen %q нелокальный, нужен --allow-remote", errUsage, listen)
}
