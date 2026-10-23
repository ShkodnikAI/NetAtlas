// Command netatlas-scan — точка входа сканера: читает ARP-таблицу
// этой машины, при флагах --ping и --names выполняет активный
// ping-sweep (ICMP) и разрешение имён (NetBIOS, mDNS, SSDP), при
// --snmp-targets опрашивает перечисленные цели по SNMP (только
// чтение), при --leases вливает DHCP-аренды из локального
// файла-выгрузки (IP, имя, SSID) — всё строго внутри границ из флага
// --subnets, и печатает результат в JSON. Производитель (vendor)
// определяется по MAC из встроенного реестра IEEE MA-L, без сети.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"

	"github.com/ShkodnikAI/NetAtlas/internal/model"
	"github.com/ShkodnikAI/NetAtlas/scanner"
	"github.com/ShkodnikAI/NetAtlas/scanner/arp"
	"github.com/ShkodnikAI/NetAtlas/scanner/dhcp"
	"github.com/ShkodnikAI/NetAtlas/scanner/ping"
	"github.com/ShkodnikAI/NetAtlas/scanner/pipeline"
	"github.com/ShkodnikAI/NetAtlas/scanner/snmp"
)

func main() {
	os.Exit(run())
}

func run() int {
	return runWith(os.Args[1:], os.Getenv, os.Stdout, os.Stderr, realWalker)
}

// scanOutput — JSON-вывод: результат сканера плюс SNMP-сбор, если он
// запрашивался. Ключ snmp присутствует всегда (пустой [] без целей).
type scanOutput struct {
	scanner.Result
	Snmp     []snmp.TargetResult `json:"snmp"`
	Topology model.Topology      `json:"topology"`
}

// walkerFactory — фабрика Walker'а для одной цели: настоящая
// реализация открывает UDP-сокет и говорит по SNMP, в тестах
// подменяется подставной, чтобы тесты не отправляли реальных пакетов.
type walkerFactory = pipeline.WalkerFactory

// realWalker — настоящая фабрика: walker поверх gosnmp.
func realWalker(target netip.Addr, auth snmp.Auth) (snmp.Walker, error) {
	return snmp.NewGoWalker(target, auth)
}

// runWith — исполнимая часть CLI: аргументы, источник переменных
// окружения, выводы и фабрика walker'ов выделены для герметичных
// тестов; nil-фабрика означает настоящую реализацию.
func runWith(args []string, getenv func(string) string, stdout, stderr io.Writer, newWalker walkerFactory) int {
	if newWalker == nil {
		newWalker = realWalker
	}
	fs := flag.NewFlagSet("netatlas-scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	subnets := fs.String("subnets", "", "список CIDR через запятую (обязателен)")
	allowLarge := fs.Bool("allow-large", false, "разрешить подсеть шире /22 (более 1024 адресов)")
	pingFlag := fs.Bool("ping", false, "активный ping-sweep подсети (ICMP; нужны права на raw-сокет)")
	namesFlag := fs.Bool("names", false, "разрешение имён (NetBIOS, mDNS, SSDP)")
	snmpTargets := fs.String("snmp-targets", "", "цели SNMP (только чтение) через запятую; каждая обязана быть внутри --subnets")
	snmpV2C := fs.Bool("snmp-v2c", false, "SNMPv2c вместо SNMPv3 authPriv (SHA/AES)")
	leasesPath := fs.String("leases", "", "файл DHCP-аренд (isc или csv); читается только локально")
	leasesFormat := fs.String("leases-format", "", "формат файла аренд: isc или csv (обязателен вместе с --leases)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	if *subnets == "" {
		fmt.Fprintln(stderr, "ошибка: нужен флаг --subnets (список CIDR через запятую)")
		return 2
	}
	scope, err := scanner.NewScope(strings.Split(*subnets, ","), *allowLarge)
	if err != nil {
		fmt.Fprintf(stderr, "ошибка: %v\n", err)
		return 2
	}

	// Файл аренд читается только локально и целиком до сканирования:
	// невалидная пара флагов — код 2, ошибка файла — код 1.
	var leaseRes *dhcp.Result
	if (*leasesPath == "") != (*leasesFormat == "") {
		fmt.Fprintln(stderr, "ошибка: флаги --leases и --leases-format указываются вместе")
		return 2
	}
	if *leasesPath != "" {
		if *leasesFormat != "isc" && *leasesFormat != "csv" {
			fmt.Fprintf(stderr, "ошибка: --leases-format %q: ждём isc или csv\n", *leasesFormat)
			return 2
		}
		f, ferr := os.Open(*leasesPath)
		if ferr != nil {
			fmt.Fprintf(stderr, "ошибка: файл аренд: %v\n", ferr)
			return 1
		}
		res, perr := dhcp.ParseLeases(f, *leasesFormat)
		cerr := f.Close()
		if perr != nil {
			fmt.Fprintf(stderr, "ошибка: файл аренд: %v\n", perr)
			return 1
		}
		if cerr != nil {
			fmt.Fprintf(stderr, "ошибка: файл аренд: %v\n", cerr)
			return 1
		}
		leaseRes = &res
	}

	limiter, err := scanner.NewLimiter(scanner.DefaultParallel, scanner.DefaultPerSecond, nil)
	if err != nil {
		fmt.Fprintf(stderr, "ошибка: %v\n", err)
		return 1
	}

	ctx := context.Background()

	cfg := pipeline.Config{Scope: scope, Limiter: limiter, Ping: *pingFlag, Names: *namesFlag}
	deps := pipeline.Deps{
		ReadARP: arp.ReadSystem,
		NewProber: func() (ping.Prober, func(), error) {
			p, err := ping.NewICMPProber()
			return p, func() { _ = p.Close() }, err
		},
		NewNameConn: func() (net.PacketConn, error) { return net.ListenPacket("udp4", ":0") },
		NewWalker:   newWalker,
	}

	if *snmpTargets != "" {
		targets, err := parseTargets(*snmpTargets)
		if err != nil {
			fmt.Fprintf(stderr, "ошибка: %v\n", err)
			return 2
		}
		if err := snmp.CheckTargets(scope, targets); err != nil {
			fmt.Fprintf(stderr, "ошибка: %v\n", err)
			return 2
		}
		auth, missing := snmpAuth(getenv, *snmpV2C)
		if len(missing) > 0 {
			fmt.Fprintf(stderr, "ошибка: не хватает переменных окружения: %s\n", strings.Join(missing, ", "))
			return 2
		}
		cfg.SNMPTargets = targets
		cfg.SNMPAuth = auth
	}
	cfg.Leases = leaseRes

	out := scanOutput{Snmp: []snmp.TargetResult{}, Topology: model.NewTopology()}
	res, err := pipeline.Run(ctx, cfg, deps)
	if err != nil {
		fmt.Fprintf(stderr, "ошибка: %v\n", err)
		return 1
	}
	if leaseRes != nil {
		fmt.Fprintf(stderr, "аренды: получено %d, пропущено %d\n", len(leaseRes.Leases), leaseRes.Skipped)
	}
	out.Result = scanner.Result{Devices: res.Devices, Hosts: res.Hosts}
	out.Snmp = res.Snmp
	out.Topology = res.Topology

	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		fmt.Fprintf(stderr, "ошибка: %v\n", err)
		return 1
	}
	return 0
}

// parseTargets разбирает список целей --snmp-targets.
func parseTargets(s string) ([]netip.Addr, error) {
	parts := strings.Split(s, ",")
	targets := make([]netip.Addr, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		a, err := netip.ParseAddr(p)
		if err != nil {
			return nil, fmt.Errorf("цель %q не IPv4-адрес", p)
		}
		targets = append(targets, a)
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("список целей пуст")
	}
	return targets, nil
}

// snmpAuth собирает учётные данные из переменных окружения. Значения
// не попадают ни в ошибки, ни в вывод — только имена переменных.
func snmpAuth(getenv func(string) string, v2c bool) (snmp.Auth, []string) {
	if v2c {
		c := getenv("NETATLAS_SNMP_COMMUNITY")
		if c == "" {
			return snmp.Auth{}, []string{"NETATLAS_SNMP_COMMUNITY"}
		}
		return snmp.Auth{V2C: true, Community: c}, nil
	}
	var missing []string
	user, authPass, privPass := getenv("NETATLAS_SNMP_USER"), getenv("NETATLAS_SNMP_AUTH_PASS"), getenv("NETATLAS_SNMP_PRIV_PASS")
	if user == "" {
		missing = append(missing, "NETATLAS_SNMP_USER")
	}
	if authPass == "" {
		missing = append(missing, "NETATLAS_SNMP_AUTH_PASS")
	}
	if privPass == "" {
		missing = append(missing, "NETATLAS_SNMP_PRIV_PASS")
	}
	if len(missing) > 0 {
		return snmp.Auth{}, missing
	}
	return snmp.Auth{User: user, AuthPass: authPass, PrivPass: privPass}, nil
}
