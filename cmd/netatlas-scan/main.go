// Command netatlas-scan — точка входа сканера: читает ARP-таблицу
// этой машины и печатает найденные устройства в JSON на stdout.
// Активных сетевых запросов нет: только локальная ARP-таблица
// и границы из флага --subnets.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ShkodnikAI/NetAtlas/scanner"
	"github.com/ShkodnikAI/NetAtlas/scanner/arp"
)

func main() {
	os.Exit(run())
}

func run() int {
	subnets := flag.String("subnets", "", "список CIDR через запятую (обязателен)")
	allowLarge := flag.Bool("allow-large", false, "разрешить подсети шире /22 (более 1024 адресов)")
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

	entries, err := arp.ReadSystem(context.Background())
	if err != nil {
		fmt.Fprintf(os.Stderr, "ошибка: %v\n", err)
		return 1
	}

	devices := scanner.FromARP(entries, scope, time.Now())
	out, err := json.MarshalIndent(devices, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "ошибка: %v\n", err)
		return 1
	}
	fmt.Println(string(out))
	return 0
}
