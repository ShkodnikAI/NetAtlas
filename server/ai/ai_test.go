// Тесты провайдеров ИИ (NR-013): внешний API получает только
// очищенную строку отчёта, ключ только из переменной окружения;
// локальная модель — только loopback. Реальной сети в тестах нет —
// только httptest.
package ai

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestExternalProviderAsk — тело только с полем report, ключ из
// переменной окружения, ответ разбирается как текст.
func TestExternalProviderAsk(t *testing.T) {
	var gotAuth string
	var gotBody map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &gotBody)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"answer":"Предлагаю заменить кабель"}`))
	}))
	defer srv.Close()

	t.Setenv("NETATLAS_TEST_AI_KEY", "stub-value-2026")
	p := ExternalProvider{Endpoint: srv.URL, KeyEnv: "NETATLAS_TEST_AI_KEY"}
	answer, err := p.Ask(context.Background(), "ОЧИЩЕННЫЙ ТЕКСТ ОТЧЁТА")
	if err != nil {
		t.Fatalf("ask: %v", err)
	}
	if answer != "Предлагаю заменить кабель" {
		t.Fatalf("ответ: %q", answer)
	}
	if gotAuth != "Bearer stub-value-2026" {
		t.Fatalf("authorization: %q", gotAuth)
	}
	if len(gotBody) != 1 || gotBody["report"] != "ОЧИЩЕННЫЙ ТЕКСТ ОТЧЁТА" {
		t.Fatalf("тело провайдеру уходит не только с отчётом: %v", gotBody)
	}
	// Ключ не задан — отказ без сети.
	p2 := ExternalProvider{Endpoint: srv.URL, KeyEnv: "NETATLAS_TEST_AI_MISSING"}
	if _, err := p2.Ask(context.Background(), "x"); err == nil {
		t.Fatal("запрос без ключа прошёл")
	}
}

// TestLocalProviderLoopbackOnly — адрес не 127.0.0.1 отклоняется до
// запроса; loopback-адрес работает (httptest слушает на 127.0.0.1).
func TestLocalProviderLoopbackOnly(t *testing.T) {
	p := LocalProvider{Addr: "192.168.1.10:11434"}
	if _, err := p.Ask(context.Background(), "x"); err == nil {
		t.Fatal("нелокальный адрес принят")
	}

	var gotBody map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &gotBody)
		_, _ = w.Write([]byte(`{"answer":"локальный ответ"}`))
	}))
	defer srv.Close()

	local := LocalProvider{Addr: srv.Listener.Addr().String()}
	answer, err := local.Ask(context.Background(), "ОЧИЩЕННЫЙ ТЕКСТ")
	if err != nil {
		t.Fatalf("ask: %v", err)
	}
	if answer != "локальный ответ" {
		t.Fatalf("ответ: %q", answer)
	}
	if len(gotBody) != 1 || gotBody["report"] != "ОЧИЩЕННЫЙ ТЕКСТ" {
		t.Fatalf("тело: %v", gotBody)
	}
}

// TestNewConfigDefaults — без ai_enabled всегда ручной режим.
func TestNewConfigDefaults(t *testing.T) {
	p := New(Config{Endpoint: "http://example.invalid", KeyEnv: "X"})
	if p.Name() != "manual" {
		t.Fatal("без Enabled провайдер не ручной")
	}
	if p2 := New(Config{Enabled: true, Endpoint: "http://example.invalid", KeyEnv: "X"}); p2.Name() != "external" {
		t.Fatal("Enabled + Endpoint → не внешний")
	}
	if p3 := New(Config{Enabled: true, LocalAddr: "127.0.0.1:11434"}); p3.Name() != "local" {
		t.Fatal("Enabled + LocalAddr → не локальный")
	}
}
