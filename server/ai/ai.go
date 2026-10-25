// Package ai — подключение модели (NR-013): провайдер вызывается
// только здесь (не из reports) и получает только строку очищенного
// отчёта. Подключение выключено по умолчанию (ai_enabled): включает
// владелец с записью в аудит; в тестах реальных вызовов нет.
package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

// MaxReportBytes — предел строки отчёта для провайдера.
const MaxReportBytes = 512 << 10

// Provider — источник ответа на очищенный отчёт. Ответ — всегда
// текст-предложение.
type Provider interface {
	// Ask получает только очищенную строку отчёта.
	Ask(ctx context.Context, cleanedReport string) (string, error)
	// Name — имя провайдера (для аудита и экрана).
	Name() string
}

// ErrDisabled — провайдер не подключён (ai_enabled=false).
var ErrDisabled = errors.New("ai: подключение модели выключено (ai_enabled)")

// ManualProvider — режим по умолчанию: копировать и вставить.
type ManualProvider struct{}

// Ask — ручной режим ответа не вызывает.
func (ManualProvider) Ask(context.Context, string) (string, error) {
	return "", ErrDisabled
}

// Name — имя режима.
func (ManualProvider) Name() string { return "manual" }

// ExternalProvider — внешний HTTP API. Ключ только из переменной
// окружения (не хранится в базе и не логируется).
type ExternalProvider struct {
	// Endpoint — адрес API (из конфигурации запуска).
	Endpoint string
	// KeyEnv — имя переменной окружения с ключом.
	KeyEnv string
	// Client — подменяемый HTTP-клиент (в тестах не вызывается
	// реальная сеть).
	Client *http.Client
}

// Name — имя режима.
func (p ExternalProvider) Name() string { return "external" }

// Ask — отправка очищенного текста внешнему API. Тело — только
// строка отчёта; ответ — только текст.
func (p ExternalProvider) Ask(ctx context.Context, cleanedReport string) (string, error) {
	if p.Endpoint == "" {
		return "", errors.New("ai: адрес внешнего API не задан")
	}
	if len(cleanedReport) > MaxReportBytes {
		return "", errors.New("ai: отчёт длиннее лимита")
	}
	key := os.Getenv(p.KeyEnv)
	if key == "" {
		return "", fmt.Errorf("ai: ключ не задан (переменная %s)", p.KeyEnv)
	}
	client := p.Client
	if client == nil {
		client = &http.Client{Timeout: 2 * time.Minute}
	}
	body, err := json.Marshal(map[string]string{"report": cleanedReport})
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.Endpoint, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+key)
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("ai: внешний API: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("ai: внешний API: код %d", resp.StatusCode)
	}
	var out struct {
		Answer string `json:"answer"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("ai: ответ не разбирается: %w", err)
	}
	return strings.TrimSpace(out.Answer), nil
}

// LocalProvider — локальная модель: адрес только 127.0.0.1.
type LocalProvider struct {
	// Addr — адрес локального сервера модели (только loopback).
	Addr   string
	Client *http.Client
}

// Name — имя режима.
func (p LocalProvider) Name() string { return "local" }

// Ask — отправка локальной модели на 127.0.0.1.
func (p LocalProvider) Ask(ctx context.Context, cleanedReport string) (string, error) {
	addr := p.Addr
	if addr == "" {
		addr = "127.0.0.1:11434"
	}
	host := addr
	if i := strings.LastIndex(addr, ":"); i > 0 {
		host = addr[:i]
	}
	if host != "127.0.0.1" && host != "[::1]" && host != "localhost" {
		return "", errors.New("ai: локальная модель — только 127.0.0.1")
	}
	client := p.Client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Minute}
	}
	body, err := json.Marshal(map[string]string{"report": cleanedReport})
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"http://"+addr+"/api/answer", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("ai: локальная модель: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("ai: локальная модель: код %d", resp.StatusCode)
	}
	var out struct {
		Answer string `json:"answer"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("ai: ответ не разбирается: %w", err)
	}
	return strings.TrimSpace(out.Answer), nil
}

// Build — провайдер по конфигурации: без ai_enabled — ручной.
type Config struct {
	Enabled   bool
	Endpoint  string // внешний API (из конфигурации запуска)
	KeyEnv    string
	LocalAddr string
}

// New — сборка провайдера.
func New(cfg Config) Provider {
	if !cfg.Enabled {
		return ManualProvider{}
	}
	if cfg.Endpoint != "" {
		return ExternalProvider{Endpoint: cfg.Endpoint, KeyEnv: cfg.KeyEnv}
	}
	return LocalProvider{Addr: cfg.LocalAddr}
}
