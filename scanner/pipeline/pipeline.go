// Package pipeline — общий конвейер сканирования: ARP-таблица этой
// машины, ping-sweep, разрешение имён, DHCP-аренды, производитель по
// MAC, SNMP (только чтение) и граф топологии. CLI netatlas-scan и
// сервер используют один код; все зависимости, ходящие в сеть,
// подменяемы: тесты не отправляют реальных пакетов.
//
// Поведение CLI не меняется: порядок этапов и вывод повторяют прежний
// runWith из cmd/netatlas-scan.
package pipeline

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/ShkodnikAI/NetAtlas/internal/model"
	"github.com/ShkodnikAI/NetAtlas/scanner"
	"github.com/ShkodnikAI/NetAtlas/scanner/arp"
	"github.com/ShkodnikAI/NetAtlas/scanner/dhcp"
	"github.com/ShkodnikAI/NetAtlas/scanner/names"
	"github.com/ShkodnikAI/NetAtlas/scanner/ping"
	"github.com/ShkodnikAI/NetAtlas/scanner/snmp"
	"github.com/ShkodnikAI/NetAtlas/scanner/topology"
)

// WalkerFactory — фабрика SNMP-walker для цели: настоящая
// реализация открывает UDP-сокет и говорит по SNMP, тесты подставляют
// подставную, чтобы не отправлять реальных пакетов.
type WalkerFactory func(netip.Addr, snmp.Auth) (snmp.Walker, error)

// ARPSource — источник ARP-таблицы этой машины.
type ARPSource func(ctx context.Context) ([]arp.Entry, error)

// Deps — подменяемые зависимости конвейера. nil-поля заменяются
// настоящими реализациями, кроме ReadARP: без ARP-источника
// сканирование невозможно (тест обязан подставить свой).
type Deps struct {
	ReadARP ARPSource
	// NewProber — ICMP-пробер и его закрытие.
	NewProber func() (ping.Prober, func(), error)
	// NewNameConn — UDP-сокет для клиента имён.
	NewNameConn func() (net.PacketConn, error)
	// NewWalker — фабрика SNMP-walker.
	NewWalker WalkerFactory
	// DNSResolver — обратный DNS для адресов без имён (NR-030).
	// nil — net.DefaultResolver.
	DNSResolver DNSResolver
	// ReadLocalIfaces — локальные интерфейсы этой машины (NR-030).
	// nil — net.Interfaces (только активные не-loopback).
	ReadLocalIfaces func() ([]LocalIface, error)
	// Hostname — имя этой машины для источника «local» (NR-030).
	// nil — os.Hostname.
	Hostname func() (string, error)
}

// Config — параметры одного сканирования: границы, методы, SNMP,
// аренды и устройства без глубокого опроса.
type Config struct {
	Scope   *scanner.Scope
	Limiter *scanner.Limiter
	Ping    bool
	Names   bool
	// SNMPTargets — цели SNMP (только чтение); SNMPTargets пуст —
	// SNMP не опрашивается.
	SNMPTargets []netip.Addr
	SNMPAuth    snmp.Auth
	// Leases — разобранный файл аренд (nil — без аренд).
	Leases *dhcp.Result
	// SkipDeepMACs — MAC гостей и «известных без агента»: имена
	// (NetBIOS, mDNS) и SNMP для них не запрашиваются; ARP/ping и
	// данные аренд работают как для всех.
	SkipDeepMACs map[string]bool
	// SkipSSDPForIPs — адреса гостей и «известных без агента» (NR-023):
	// ответы SSDP от них не сохраняются, присутствие не трогается.
	SkipSSDPForIPs map[string]bool
	// NoDNS отключает обратный DNS (NR-030): адресам без имён из
	// других источников net.LookupAddr не отправляется.
	NoDNS bool
	// OnStage — прогресс: вызывается по завершении каждого этапа
	// ("arp", "ping", "names", "leases", "snmp", "topology").
	OnStage func(stage string)
}

// Counters — счётчики итога сканирования для состояния и интерфейса.
type Counters struct {
	Devices       int `json:"devices"`
	Hosts         int `json:"hosts"`
	Links         int `json:"links"`
	SNMPTargets   int `json:"snmp_targets"`
	Leases        int `json:"leases"`
	LeasesSkipped int `json:"leases_skipped"`
}

// Result — итог конвейера: устройства, хосты, SNMP-сбор, топология и
// счётчики.
type Result struct {
	Devices  []model.Device      `json:"devices"`
	Hosts    []model.Host        `json:"hosts"`
	Snmp     []snmp.TargetResult `json:"snmp"`
	Topology model.Topology      `json:"topology"`
	Counts   Counters            `json:"counts"`
}

// stage фиксирует этап, если прогресс задан.
func stage(c Config, name string) {
	if c.OnStage != nil {
		c.OnStage(name)
	}
}

// Run исполняет конвейер целиком. Сеть ходит только внутри
// cfg.Scope и через cfg.Limiter; устройства из cfg.SkipDeepMACs не
// опрашиваются по именам и SNMP.
func Run(ctx context.Context, cfg Config, deps Deps) (Result, error) {
	if cfg.Scope == nil {
		return Result{}, fmt.Errorf("pipeline: границы сети не заданы")
	}
	if cfg.Limiter == nil {
		return Result{}, fmt.Errorf("pipeline: ограничитель не задан")
	}
	if deps.ReadARP == nil {
		return Result{}, fmt.Errorf("pipeline: ARP-источник не задан")
	}

	// ARP-таблица этой машины: устройства из локальных записей.
	stage(cfg, "arp")
	entries, err := deps.ReadARP(ctx)
	if err != nil {
		return Result{}, fmt.Errorf("pipeline: arp: %w", err)
	}

	now := nowOf(ctx)
	opt := scanner.Options{Now: now}
	if cfg.Ping {
		if deps.NewProber == nil {
			return Result{}, fmt.Errorf("pipeline: ping включён, но пробер не задан")
		}
		p, closeP, err := deps.NewProber()
		if err != nil {
			return Result{}, fmt.Errorf("pipeline: пробер: %w", err)
		}
		defer closeP()
		opt.Ping = true
		opt.Prober = p
	}
	if cfg.Names {
		if deps.NewNameConn == nil {
			return Result{}, fmt.Errorf("pipeline: имена включены, но сокет не задан")
		}
		conn, err := deps.NewNameConn()
		if err != nil {
			return Result{}, fmt.Errorf("pipeline: сокет имён: %w", err)
		}
		client := names.NewClient(conn)
		defer client.Close()
		opt.Names = true
		opt.NameClient = client
	}
	if len(cfg.SkipDeepMACs) > 0 {
		opt.SkipNamesForMACs = cfg.SkipDeepMACs
	}
	opt.SkipSSDPForIPs = cfg.SkipSSDPForIPs

	res, err := scanner.Run(ctx, entries, cfg.Scope, cfg.Limiter, opt)
	if err != nil {
		return Result{}, err
	}
	if cfg.Ping {
		stage(cfg, "ping")
	}
	if cfg.Names {
		stage(cfg, "names")
	}

	// Свежая ARP-таблица после обхода (NR-030): за время ping и имён
	// кэш пополнился — живой адрес получает MAC, если запись появилась,
	// и хост без MAC становится устройством. Ошибка повторного чтения
	// не отбрасывает собранный результат.
	if cfg.Ping {
		if again, aerr := deps.ReadARP(ctx); aerr == nil {
			res.Devices, res.Hosts = mergeDevices(res.Devices, res.Hosts,
				scanner.FromARP(again, cfg.Scope, now), now)
		}
	}

	// Локальные интерфейсы (NR-030): эта машина присутствует на карте
	// как устройство с MAC, наблюдением «local» и именем из hostname.
	// Запись ip:<адрес> под тем же адресом заменяется при сохранении
	// (логика SaveScan, NR-023).
	if local, lerr := localDevices(cfg.Scope, deps, now); lerr == nil && len(local) > 0 {
		res.Devices, res.Hosts = mergeDevices(res.Devices, res.Hosts, local, now)
	}

	// Аренды вливаются до SNMP и топологии: арендные устройства
	// попадают в граф.
	leases, skipped := 0, 0
	if cfg.Leases != nil {
		stage(cfg, "leases")
		res.Devices = scanner.AddLeases(res.Devices, cfg.Leases.Leases, cfg.Scope, nowOf(ctx))
		leases, skipped = len(cfg.Leases.Leases), cfg.Leases.Skipped
	}
	res.Devices = scanner.FillVendors(res.Devices)

	// Обратный DNS (NR-030): адресам без имён — по одному LookupAddr
	// внутри границ, под лимитером. Отключается cfg.NoDNS.
	if !cfg.NoDNS {
		if err := reverseDNS(ctx, res.Devices, res.Hosts, cfg.Scope, cfg.Limiter, deps.DNSResolver, now); err != nil {
			return Result{}, err
		}
	}

	out := Result{
		Devices:  res.Devices,
		Hosts:    res.Hosts,
		Snmp:     []snmp.TargetResult{},
		Topology: model.NewTopology(),
		Counts:   Counters{Devices: len(res.Devices), Hosts: len(res.Hosts), Leases: leases, LeasesSkipped: skipped},
	}

	// SNMP только чтение; цели внутри границ проверены вызывающим
	// (CLI: parseTargets+CheckTargets, сервер: Scope). Гости и
	// «известные без агента» исключаются из целей.
	if len(cfg.SNMPTargets) > 0 {
		stage(cfg, "snmp")
		targets := skipGuestTargets(cfg.SNMPTargets, res.Devices, cfg.SkipDeepMACs)
		out.Snmp = collectSNMP(ctx, targets, cfg.SNMPAuth, cfg.Limiter, deps.NewWalker)
		out.Counts.SNMPTargets = len(out.Snmp)
		out.Topology = topology.Build(res.Devices, out.Snmp)
		stage(cfg, "topology")
	}
	out.Counts.Links = len(out.Topology.Links)
	return out, nil
}

// skipGuestTargets убирает из целей SNMP адреса устройств без
// глубокого опроса.
func skipGuestTargets(targets []netip.Addr, devices []model.Device, skip map[string]bool) []netip.Addr {
	if len(skip) == 0 {
		return targets
	}
	guestIP := make(map[string]bool)
	for _, d := range devices {
		if !skip[d.ID] {
			continue
		}
		for _, ip := range d.IPs {
			guestIP[ip.String()] = true
		}
	}
	out := make([]netip.Addr, 0, len(targets))
	for _, t := range targets {
		if !guestIP[t.String()] {
			out = append(out, t)
		}
	}
	return out
}

// collectSNMP опрашивает цели по очереди; неответившая цель даёт
// запись с полем error, остальные цели обрабатываются дальше.
func collectSNMP(ctx context.Context, targets []netip.Addr, auth snmp.Auth, limiter *scanner.Limiter, newWalker WalkerFactory) []snmp.TargetResult {
	out := make([]snmp.TargetResult, 0, len(targets))
	for _, t := range targets {
		tr := snmp.NewTargetResult(t)
		if newWalker == nil {
			tr.Error = "pipeline: фабрика SNMP-walker не задана"
			out = append(out, tr)
			continue
		}
		w, err := newWalker(t, auth)
		if err == nil {
			res, cerr := snmp.Collect(ctx, snmp.NewLimitedWalker(w, limiter))
			_ = w.Close()
			if cerr == nil {
				tr.Fill(res)
			} else {
				tr.Error = cerr.Error()
			}
		} else {
			tr.Error = err.Error()
		}
		out = append(out, tr)
	}
	return out
}

// nowOf — время сканирования: контекст не несёт времени, поэтому
// используется текущее (тесты подменяют опции через scanner.Run при
// необходимости; детерминизм не требуется).
func nowOf(_ context.Context) time.Time {
	return time.Now()
}
