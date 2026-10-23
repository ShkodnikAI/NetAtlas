package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/ShkodnikAI/NetAtlas/scanner"
)

// config — параметры запуска сервера.
type config struct {
	dbPath      string
	listen      string
	allowRemote bool
	allowLarge  bool
	scope       *scanner.Scope
	token       string
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
	scope, err := scanner.NewScope(list, cfg.allowLarge)
	if err != nil {
		return config{}, fmt.Errorf("%w: --subnets: %v", errUsage, err)
	}
	cfg.scope = scope

	cfg.token = getenv("NETATLAS_TOKEN")
	if cfg.token == "" {
		return config{}, fmt.Errorf("%w: переменная окружения NETATLAS_TOKEN не задана", errUsage)
	}
	if len(cfg.token) < 24 {
		return config{}, fmt.Errorf("%w: NETATLAS_TOKEN короче 24 символов", errUsage)
	}
	return cfg, nil
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
