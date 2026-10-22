// Command netatlas-scan — точка входа сканера: читает ARP-таблицу
// этой машины, при флагах --ping и --names выполняет активный
// ping-sweep (ICMP) и разрешение имён (NetBIOS, mDNS, SSDP) строго
// внутри границ из флага --subnets, и печатает результат в JSON.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/ShkodnikAI/NetAtlas/scanner"
	"github.com/ShkodnikAI/NetAtlas/scanner/arp"
	"github.com/ShkodnikAI/NetAtlas/scanner/names"
	"github.com/ShkodnikAI/NetAtlas/scanner/ping"
)

func main() {
	os.Exit(run())
}

func run() int {
	subnets := flag.String("subnets", "", "список CIDR через запятую (обязателен)")
	allowLarge := flag.Bool("allow-large", false, "разрешить подсеть шире /22 (более 1024 адресов)")
	pingFlag := flag.Bool("ping", false, "активный ping-sweep подсети (ICMP; нужны права на raw-сокет)")
	namesFlag := flag.Bool("names", false, "разрешение имён (NetBIOS, mDNS, SSDP)")
	flag.Parse()

	if *subnets == "" {
		fmt.Fprintln(os.Stderr, "ошибка: нужен флаг --subnets (список CIDR через запятую)")
		return 2
	}
	scope, err := scanner.NewScope(strings.Split(*subnets, ","), *allowLarge)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ошибка: %v\n", err)
		return 2
	}

	limiter, err := scanner.NewLimiter(scanner.DefaultParallel, scanner.DefaultPerSecond, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ошибка: %v\n", err)
		return 1
	}

	entries, err := arp.ReadSystem(context.Background())
	if err != nil {
		fmt.Fprintf(os.Stderr, "ошибка: %v\n", err)
		return 1
	}

	opt := scanner.Options{Now: time.Now()}

	if *pingFlag {
		p, err := ping.NewICMPProber()
		if err != nil {
			fmt.Fprintf(os.Stderr, "ошибка: %v\n", err)
			return 1
		}
		defer p.Close()
		opt.Ping = true
		opt.Prober = p
	}

	if *namesFlag {
		conn, err := net.ListenPacket("udp4", ":0")
		if err != nil {
			fmt.Fprintf(os.Stderr, "ошибка: не удалось открыть UDP-сокет: %v\n", err)
			return 1
		}
		client := names.NewClient(conn)
		defer client.Close()
		opt.Names = true
		opt.NameClient = client
	}

	result, err := scanner.Run(context.Background(), entries, scope, limiter, opt)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ошибка: %v\n", err)
		return 1
	}

	out, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "ошибка: %v\n", err)
		return 1
	}
	fmt.Println(string(out))
	return 0
}
