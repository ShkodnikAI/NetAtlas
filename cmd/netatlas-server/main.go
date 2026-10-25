// Command netatlas-server — сервер карты сети NetAtlas: HTTP API
// поверх хранилища. Слушает 127.0.0.1:8484 по умолчанию; всё, что
// идёт в сеть (только ping при проверке), идёт только внутри
// подсетей --subnets и через лимитер.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ShkodnikAI/NetAtlas/internal/version"
	"github.com/ShkodnikAI/NetAtlas/pki"
	"github.com/ShkodnikAI/NetAtlas/rules"
	"github.com/ShkodnikAI/NetAtlas/scanner"
	"github.com/ShkodnikAI/NetAtlas/scanner/arp"
	"github.com/ShkodnikAI/NetAtlas/scanner/ping"
	"github.com/ShkodnikAI/NetAtlas/scanner/snmp"
	"github.com/ShkodnikAI/NetAtlas/server/agentapi"
	"github.com/ShkodnikAI/NetAtlas/server/ai"
	"github.com/ShkodnikAI/NetAtlas/server/api"
	"github.com/ShkodnikAI/NetAtlas/server/audit"
	"github.com/ShkodnikAI/NetAtlas/server/metrics"
	"github.com/ShkodnikAI/NetAtlas/server/store"
	"github.com/ShkodnikAI/NetAtlas/web"
)

func main() {
	cfg, err := parseConfig(os.Args[1:], os.Getenv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "netatlas-server: %v\n", err)
		os.Exit(2)
	}
	if cfg.showVersion {
		fmt.Println(version.String())
		return
	}
	if err := run(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "netatlas-server: %v\n", err)
		os.Exit(1)
	}
}

// run — запуск сервера: хранилище, границы сети, HTTP, корректное
// завершение по сигналу.
func run(cfg config) error {
	st, err := store.Open(cfg.dbPath)
	if err != nil {
		return fmt.Errorf("хранилище: %w", err)
	}
	defer st.Close()

	limiter, err := scanner.NewLimiter(scanner.DefaultParallel, scanner.DefaultPerSecond, nil)
	if err != nil {
		return fmt.Errorf("лимитер: %w", err)
	}

	// Пробер живости: если права на ICMP недоступны, сервер работает,
	// но проверка отвечает 503 (нет пробера).
	var prober api.Prober
	if p, err := ping.NewICMPProber(); err != nil {
		fmt.Fprintf(os.Stderr, "netatlas-server: проверка живости недоступна: %v\n", err)
	} else {
		defer p.Close()
		prober = p
	}

	handler, err := api.New(st, cfg.token, cfg.scope, limiter, prober)
	if err != nil {
		return fmt.Errorf("api: %w", err)
	}

	// Цепочка журнала аудита проверяется при старте (NR-023): разрыв
	// не мешает работе (сервер стартует), но пишется в stderr и
	// отдаётся интерфейсу через /api/config (audit_ok: false).
	if err := audit.Verify(context.Background(), st.DB()); err != nil {
		handler.SetAuditOK(false)
		fmt.Fprintf(os.Stderr, "audit: цепочка нарушена: %v\n", err)
	}

	// Движок правил (NR-009): встроенные данные или --rules-dir.
	rulesEngine, err := rules.NewEngine(cfg.rulesDir)
	if err != nil {
		return fmt.Errorf("правила: %w", err)
	}
	handler.ConfigureRules(rulesEngine)

	// Подпись скриптов (NR-011): ключ читается маршрутом подписи из
	// каталога ключей в момент подписания; без каталога — 503.
	handler.ConfigureScripts(api.ScriptsConfig{KeyDir: cfg.keyDir})

	// Отчёты для ИИ (NR-013): без --ai-enabled — ручной режим
	// (копировать и вставить); маршрут ответа модели отвечает 503.
	provider := ai.New(ai.Config{
		Enabled:   cfg.aiEnabled,
		Endpoint:  cfg.aiEndpoint,
		KeyEnv:    cfg.aiKeyEnv,
		LocalAddr: cfg.aiLocalAddr,
	})
	handler.ConfigureAI(provider)
	if cfg.aiEnabled {
		// Включение — действие владельца при запуске: уходит в аудит.
		if err := st.AppendAudit(context.Background(), "server", "ai_enabled", "reports",
			"провайдер "+provider.Name()); err != nil {
			fmt.Fprintf(os.Stderr, "netatlas-server: аудит включения ИИ: %v\n", err)
		}
		fmt.Fprintf(os.Stderr, "netatlas-server: подключение модели ИИ включено (провайдер %s)\n", provider.Name())
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Качество сети (NR-008): фоновое уплотнение метрик раз в час.
	go metricsLoop(ctx, st)

	// Активность (NR-012): чистка данных старше 90 дней раз в сутки.
	go activityPurgeLoop(ctx, handler)

	// SNMP-счётчики портов: только при явных --snmp-targets.
	if len(cfg.snmpList) > 0 {
		auth, snmpReady := snmpServerAuth(os.Getenv)
		if !snmpReady {
			return fmt.Errorf("snmp: цели заданы, но учётные данные NETATLAS_SNMP_* не настроены")
		}
		task, err := metrics.NewTask(cfg.snmpList, auth, cfg.scope, st)
		if err != nil {
			return fmt.Errorf("snmp: %w", err)
		}
		if task != nil {
			go task.Loop(ctx)
		}
	}

	// Мастер сканирования: границы из --subnets, SNMP-учётные данные
	// только из окружения (в API, базу, аудит и ответы не попадают).
	auth, snmpReady := snmpServerAuth(os.Getenv)
	handler.ConfigureScan(api.ServerScanConfig{
		Subnets:   cfg.subnetList,
		SNMPAuth:  auth,
		SNMPReady: snmpReady,
	}, api.ScanDeps{
		ReadARP: arp.ReadSystem,
		NewProber: func() (ping.Prober, func(), error) {
			if prober == nil {
				return nil, nil, fmt.Errorf("проверка живости недоступна (нужны права на ICMP)")
			}
			return prober, func() {}, nil
		},
		NewNameConn: func() (net.PacketConn, error) { return net.ListenPacket("udp4", ":0") },
		NewWalker: func(target netip.Addr, auth snmp.Auth) (snmp.Walker, error) {
			return snmp.NewGoWalker(target, auth)
		},
	})

	// Корень — интерфейс (встроенная сборка web/dist), API — /api/.
	root := http.NewServeMux()
	root.Handle("/api/", handler.Handler())
	root.Handle("/", web.Handler())

	srv := &http.Server{
		Addr:              cfg.listen,
		Handler:           root,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	errCh := make(chan error, 3)

	// Агентские слушатели (NR-024): только при явных флагах, свои
	// обработчики, свой TLS; порт владельца не разделяется.
	if cfg.agentListen != "" {
		if err := startAgentListeners(ctx, cfg, st, errCh); err != nil {
			return err
		}
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	fmt.Fprintf(os.Stderr, "netatlas-server: слушаю %s (база %s)\n", cfg.listen, cfg.dbPath)
	if cfg.agentListen != "" {
		fmt.Fprintf(os.Stderr, "netatlas-server: агентский API %s (mTLS)\n", cfg.agentListen)
		if cfg.agentEnrollListen != "" {
			fmt.Fprintf(os.Stderr, "netatlas-server: регистрация агентов %s (по токену)\n", cfg.agentEnrollListen)
		}
	}
	select {
	case err := <-errCh:
		return fmt.Errorf("http: %w", err)
	case <-ctx.Done():
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("остановка http: %w", err)
	}
	return nil
}

// startAgentListeners поднимает агентские слушатели: mTLS для
// checkin/inventory и, при --agent-enroll-listen, отдельный
// слушатель регистрации. Сертификат сервера один на оба слушателя
// (выпускается один раз и хранится в каталоге ключей).
func startAgentListeners(ctx context.Context, cfg config, st *store.Store, errCh chan<- error) error {
	ca, err := pki.LoadCA(cfg.keyDir)
	if err != nil {
		return fmt.Errorf("pki: %w", err)
	}
	aa, err := agentapi.New(st, ca, 0)
	if err != nil {
		return fmt.Errorf("agentapi: %w", err)
	}
	// Диспетчеризация заданий (NR-011): только при явном флаге, ключ
	// подписи читается здесь один раз; без флага checkin задания не
	// отдаёт никогда.
	if cfg.enableDispatch {
		key, err := pki.LoadSigningKey(cfg.keyDir)
		if err != nil {
			return fmt.Errorf("pki: ключ подписи заданий: %w", err)
		}
		aa.ConfigureDispatch(&agentapi.DispatchDeps{
			AllowCustomScripts: cfg.allowCustomScripts,
			Key:                key,
		})
		fmt.Fprintf(os.Stderr, "netatlas-server: диспетчеризация заданий включена (произвольные скрипты: %v)\n", cfg.allowCustomScripts)
	}
	certPEM, keyPEM, err := pki.EnsureServerCert(cfg.keyDir)
	if err != nil {
		return fmt.Errorf("pki: сертификат сервера: %w", err)
	}
	serverCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("pki: пара сервера: %w", err)
	}
	ln, err := net.Listen("tcp", cfg.agentListen)
	if err != nil {
		return fmt.Errorf("agentapi: слушатель %s: %w", cfg.agentListen, err)
	}
	go func() {
		if err := agentapi.Serve(ctx, ln, aa.MTLSConfig(serverCert), aa.MTLSHandler()); err != nil {
			errCh <- err
		}
	}()
	if cfg.agentEnrollListen != "" {
		lnE, err := net.Listen("tcp", cfg.agentEnrollListen)
		if err != nil {
			ln.Close()
			return fmt.Errorf("agentapi: слушатель регистрации %s: %w", cfg.agentEnrollListen, err)
		}
		go func() {
			if err := agentapi.Serve(ctx, lnE, aa.EnrollConfig(serverCert), aa.EnrollHandler()); err != nil {
				errCh <- err
			}
		}()
	}
	return nil
}

// activityPurgeLoop — удаление данных активности старше 90 дней
// (NR-012) раз в сутки с записью в аудит; идемпотентно.
func activityPurgeLoop(ctx context.Context, h *api.API) {
	h.PurgeActivityNow(ctx)
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			h.PurgeActivityNow(ctx)
		}
	}
}

// metricsLoop — уплотнение метрик раз в час (NR-008): сырые →
// 5-минутные → часовые, чистка старше года. Идемпотентно.
func metricsLoop(ctx context.Context, st *store.Store) {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	if _, err := st.CompactMetrics(ctx, time.Now()); err != nil {
		fmt.Fprintf(os.Stderr, "netatlas-server: уплотнение метрик: %v\n", err)
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if res, err := st.CompactMetrics(ctx, time.Now()); err != nil {
				fmt.Fprintf(os.Stderr, "netatlas-server: уплотнение метрик: %v\n", err)
			} else if res.RawRolled+res.Agg5Rolled > 0 {
				fmt.Fprintf(os.Stderr, "netatlas-server: метрики уплотнены: сырых %d, 5м %d\n", res.RawRolled, res.Agg5Rolled)
			}
		}
	}
}
