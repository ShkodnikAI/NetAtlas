// Маршруты владельца для агентов (NR-024): выдача токена
// регистрации, список, отзыв.
package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/ShkodnikAI/NetAtlas/server/store"
)

// Токен регистрации выдаётся владельцу один раз, длинный (64 hex),
// в аудите — только хэш (настоящий store; здесь фейк — форма ответа).
func TestAgentEnrollmentRoute(t *testing.T) {
	fs := newFakeStore()
	h := testAPI(t, fs, &fakeProber{})
	rec := do(h, "POST", "/api/agents/enrollment", "", bearer)
	if rec.Code != http.StatusCreated {
		t.Fatalf("код %d, хочу 201: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Token       string `json:"token"`
		ExpiresInS  int    `json:"expires_in_s"`
		EnrollRoute string `json:"enroll_route"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("ответ не разбирается: %v", err)
	}
	if len(resp.Token) != 64 {
		t.Fatalf("токен длиной %d, хочу 64 hex-символа", len(resp.Token))
	}
	if resp.ExpiresInS != int(store.EnrollTokenTTL.Seconds()) {
		t.Fatalf("expires_in_s = %d, хочу %d", resp.ExpiresInS, int(store.EnrollTokenTTL.Seconds()))
	}
	if resp.EnrollRoute != "/agent/v1/enroll" {
		t.Fatalf("enroll_route = %q", resp.EnrollRoute)
	}
	if fs.enrollTokens != 1 {
		t.Fatalf("выдач токена = %d, хочу 1", fs.enrollTokens)
	}
	// Без токена владельца маршрут не отвечает.
	if rec := do(h, "POST", "/api/agents/enrollment", "", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("без авторизации код %d, хочу 401", rec.Code)
	}
}

// Список агентов отдаёт карточки.
func TestAgentsListRoute(t *testing.T) {
	fs := newFakeStore()
	fs.addAgent("agent:one")
	fs.addAgent("agent:two")
	h := testAPI(t, fs, &fakeProber{})
	rec := do(h, "GET", "/api/agents", "", bearer)
	if rec.Code != http.StatusOK {
		t.Fatalf("код %d, хочу 200: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Agents []store.Agent `json:"agents"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("ответ не разбирается: %v", err)
	}
	if len(resp.Agents) != 2 {
		t.Fatalf("агентов = %d, хочу 2", len(resp.Agents))
	}
	if resp.Agents[0].ID != "agent:one" || resp.Agents[0].Status != "active" {
		t.Fatalf("карточка агента: %+v", resp.Agents[0])
	}
}

// Отзыв: чужой — 404, повторный — 409, нормальный — 200.
func TestAgentRevokeRoute(t *testing.T) {
	fs := newFakeStore()
	fs.addAgent("agent:one")
	h := testAPI(t, fs, &fakeProber{})
	if rec := do(h, "POST", "/api/agents/agent:ghost/revoke", "", bearer); rec.Code != http.StatusNotFound {
		t.Fatalf("чужой агент: код %d, хочу 404", rec.Code)
	}
	rec := do(h, "POST", "/api/agents/agent:one/revoke", "", bearer)
	if rec.Code != http.StatusOK {
		t.Fatalf("отзыв: код %d, хочу 200: %s", rec.Code, rec.Body.String())
	}
	rec = do(h, "POST", "/api/agents/agent:one/revoke", "", bearer)
	if rec.Code != http.StatusConflict {
		t.Fatalf("повторный отзыв: код %d, хочу 409: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "отозван") {
		t.Fatalf("текст ошибки без пояснения: %s", rec.Body.String())
	}
	if !fs.revokedAgents["agent:one"] {
		t.Fatal("фейковый store не зафиксировал отзыв")
	}
}
