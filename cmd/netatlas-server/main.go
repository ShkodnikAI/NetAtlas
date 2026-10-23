// Command netatlas-server — сервер карты сети NetAtlas: HTTP API
// поверх хранилища. Слушает 127.0.0.1:8484 по умолчанию; всё, что
// идёт в сеть (только ping при проверке), идёт только внутри
// подсетей --subnets и через лимитер.
package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ShkodnikAI/NetAtlas/scanner"
	"github.com/ShkodnikAI/NetAtlas/scanner/ping"
	"github.com/ShkodnikAI/NetAtlas/server/api"
	"github.com/ShkodnikAI/NetAtlas/server/store"
	"github.com/ShkodnikAI/NetAtlas/web"
)

func main() {
	cfg, err := parseConfig(os.Args[1:], os.Getenv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "netatlas-server: %v\n", err)
		os.Exit(2)
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

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	fmt.Fprintf(os.Stderr, "netatlas-server: слушаю %s (база %s)\n", cfg.listen, cfg.dbPath)
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
