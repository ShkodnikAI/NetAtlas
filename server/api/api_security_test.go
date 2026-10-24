// Тесты маршрутов безопасности (NR-010) на фейковом хранилище:
// сводка с отчётами проверок и инвентарём, карточка компьютера,
// пустые данные (score = null, а не 100), отказы без правил.
package api

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/ShkodnikAI/NetAtlas/agent/collect"
	"github.com/ShkodnikAI/NetAtlas/internal/model"
	"github.com/ShkodnikAI/NetAtlas/server/store"
)

// securityEnvelope — конверт отчёта проверок для фейкового хранилища.
func securityEnvelope(tb testing.TB, results []map[string]any) string {
	tb.Helper()
	payload, err := json.Marshal(map[string]any{
		"security_schema_version": 1,
		"collected_at":            time.Now().UTC().Format(time.RFC3339),
		"results":                 results,
	})
	if err != nil {
		tb.Fatalf("payload: %v", err)
	}
	env, err := json.Marshal(map[string]any{
		"kind": "security", "schema_ver": 1,
		"collected_at": time.Now().UTC(), "results": results,
	})
	if err != nil {
		tb.Fatalf("envelope: %v", err)
	}
	_ = payload
	return string(env)
}

// Сводка: fail-проверка с весом, unknown-счётчик, инвентарь без
// замечаний. Оценка одного компьютера — 100−25.
func TestSecuritySummaryWithReports(t *testing.T) {
	fs := newFakeStore()
	fs.addAgent("agent:one")
	fs.security["agent:one"] = securityEnvelope(t, []map[string]any{
		{"id": "smbv1", "status": "fail", "detail": "SMBv1 включён"},
		{"id": "bitlocker", "status": "unknown", "detail": "командлета нет"},
		{"id": "firewall", "status": "pass"},
		{"id": "ports", "status": "pass", "detail": "слушающих портов: 2",
			"data": map[string]any{"ports": []map[string]any{{"local_address": "0.0.0.0", "local_port": 445}}}},
	})
	fs.inventory["agent:one"] = inventoryRow(t, nil)
	a := newRulesAPI(t, fs)
	rec := do(a.Handler(), "GET", "/api/security/summary", "", bearer)
	if rec.Code != http.StatusOK {
		t.Fatalf("код %d: %s", rec.Code, rec.Body.String())
	}
	var resp securitySummary
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("ответ: %v", err)
	}
	if resp.Score == nil || *resp.Score != 75 {
		t.Fatalf("оценка %+v, хочу 75", resp.Score)
	}
	if len(resp.Computers) != 1 || resp.Computers[0].Worst != "critical" {
		t.Fatalf("компьютеры: %+v", resp.Computers)
	}
	if resp.Computers[0].Unknown != 1 {
		t.Fatalf("unknown-проверок: %d, хочу 1", resp.Computers[0].Unknown)
	}
	if resp.UnknownChecks != 1 {
		t.Fatalf("сводный unknown: %d", resp.UnknownChecks)
	}
	if resp.Counts["critical"] != 1 || resp.Counts["warning"] != 0 {
		t.Fatalf("счётчики: %+v", resp.Counts)
	}
	if len(resp.Findings) != 1 || resp.Findings[0].RuleID != "sec_smbv1_enabled" {
		t.Fatalf("замечания: %+v", resp.Findings)
	}
	if len(resp.Findings[0].Where) != 1 || resp.Findings[0].Where[0] != "pc" {
		t.Fatalf("where: %+v", resp.Findings[0].Where)
	}
	if resp.Findings[0].Basis == "" {
		t.Fatal("основание обязательно")
	}
	// Порты — данные, не замечание: в группах их нет.
	if len(resp.Network) != 0 {
		t.Fatalf("сетевых замечаний без SNMP-наблюдений быть не должно: %+v", resp.Network)
	}
}

// Без данных оценка null: «нет данных», а не «всё безопасно».
func TestSecuritySummaryEmpty(t *testing.T) {
	fs := newFakeStore()
	fs.addAgent("agent:none")
	a := newRulesAPI(t, fs)
	rec := do(a.Handler(), "GET", "/api/security/summary", "", bearer)
	if rec.Code != http.StatusOK {
		t.Fatalf("код %d", rec.Code)
	}
	var resp securitySummary
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("ответ: %v", err)
	}
	if resp.Score != nil {
		t.Fatalf("оценка без данных должна быть null, получена %v", *resp.Score)
	}
	if len(resp.Computers) != 0 {
		t.Fatalf("компьютеров без данных быть не должно: %+v", resp.Computers)
	}
}

// Инвентарь участвует: ОС вне поддержки (os_out_of_support в таблице
// весов) и устаревшее ПО дают замечания без отчёта проверок.
func TestSecuritySummaryInventoryFindings(t *testing.T) {
	fs := newFakeStore()
	fs.addAgent("agent:old")
	fs.inventory["agent:old"] = inventoryRow(t, func(rep *collect.Report) {
		rep.OS = &collect.OSInfo{Caption: "Microsoft Windows 10 Pro", BuildNumber: "19045"}
		rep.Programs = []collect.Program{{Name: "Google Chrome", Version: "90.0"}}
	})
	a := newRulesAPI(t, fs)
	rec := do(a.Handler(), "GET", "/api/security/summary", "", bearer)
	if rec.Code != http.StatusOK {
		t.Fatalf("код %d: %s", rec.Code, rec.Body.String())
	}
	var resp securitySummary
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("ответ: %v", err)
	}
	rules := map[string]bool{}
	for _, f := range resp.Findings {
		rules[f.RuleID] = true
	}
	if !rules["os_out_of_support"] {
		t.Fatalf("нет замечания по ОС: %+v", resp.Findings)
	}
	if !rules["sec_software_outdated"] {
		t.Fatalf("нет замечания по ПО: %+v", resp.Findings)
	}
	if resp.Score == nil || *resp.Score != 70 {
		t.Fatalf("оценка %+v, хочу 70 (100−20−10)", resp.Score)
	}
	// Отчёта проверок нет: в общую оценку компьютер не входит.
	if len(resp.Computers) != 1 {
		t.Fatalf("компьютер с инвентарём должен быть в списке: %+v", resp.Computers)
	}
}

// Сетевые замечания из наблюдений сканера (snmp, snmp_v2c).
func TestSecuritySummaryNetwork(t *testing.T) {
	fs := newFakeStore()
	fs.devices["aa:bb:cc:00:00:01"] = store.DeviceInfo{
		ID: "aa:bb:cc:00:00:01", Hostname: "sw-core", Class: "managed",
		Observations: []model.Observation{{Source: "ping"}, {Source: "snmp"}, {Source: "snmp_v2c"}},
	}
	a := newRulesAPI(t, fs)
	rec := do(a.Handler(), "GET", "/api/security/summary", "", bearer)
	if rec.Code != http.StatusOK {
		t.Fatalf("код %d: %s", rec.Code, rec.Body.String())
	}
	var resp securitySummary
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("ответ: %v", err)
	}
	if len(resp.Network) != 2 {
		t.Fatalf("сетевых замечаний: %d, хочу 2: %+v", len(resp.Network), resp.Network)
	}
	seen := map[string]bool{}
	for _, g := range resp.Network {
		seen[g.RuleID] = true
		if len(g.Where) != 1 || g.Where[0] != "aa:bb:cc:00:00:01" {
			t.Fatalf("where: %+v", g.Where)
		}
	}
	if !seen["sec_snmp_admin_open"] || !seen["sec_snmp_v2c_enabled"] {
		t.Fatalf("правила: %+v", resp.Network)
	}
}

// Карточка компьютера: проверки, замечания, порты из данных.
func TestSecurityComputerCard(t *testing.T) {
	fs := newFakeStore()
	fs.addAgent("agent:card")
	fs.security["agent:card"] = securityEnvelope(t, []map[string]any{
		{"id": "firewall", "status": "fail", "detail": "профиль выключен: Public"},
		{"id": "ports", "status": "pass", "detail": "слушающих портов: 1",
			"data": map[string]any{"ports": []map[string]any{{"local_address": "0.0.0.0", "local_port": 3389, "process": "TermService"}}}},
	})
	a := newRulesAPI(t, fs)
	rec := do(a.Handler(), "GET", "/api/security/computers/agent:card", "", bearer)
	if rec.Code != http.StatusOK {
		t.Fatalf("код %d: %s", rec.Code, rec.Body.String())
	}
	var card securityCard
	if err := json.Unmarshal(rec.Body.Bytes(), &card); err != nil {
		t.Fatalf("ответ: %v", err)
	}
	if card.Score == nil || *card.Score != 80 {
		t.Fatalf("оценка %+v, хочу 80", card.Score)
	}
	if len(card.Checks) != 2 {
		t.Fatalf("проверок: %d", len(card.Checks))
	}
	if len(card.Findings) != 1 || card.Findings[0].Weight != 20 {
		t.Fatalf("замечания: %+v", card.Findings)
	}
	if len(card.Ports) != 1 || card.Ports[0].LocalPort != 3389 || card.Ports[0].Process != "TermService" {
		t.Fatalf("порты: %+v", card.Ports)
	}
	// Неизвестный агент — 404.
	if rec := do(a.Handler(), "GET", "/api/security/computers/agent:missing", "", bearer); rec.Code != http.StatusNotFound {
		t.Fatalf("неизвестный агент: код %d, хочу 404", rec.Code)
	}
	// Агент без данных — 404 с пояснением.
	fs2 := newFakeStore()
	fs2.addAgent("agent:empty")
	a2 := newRulesAPI(t, fs2)
	if rec := do(a2.Handler(), "GET", "/api/security/computers/agent:empty", "", bearer); rec.Code != http.StatusNotFound {
		t.Fatalf("агент без данных: код %d, хочу 404", rec.Code)
	}
}

// Без движка правил маршруты безопасности отвечают 503.
func TestSecurityRulesNotConfigured503(t *testing.T) {
	h := testAPI(t, newFakeStore(), &fakeProber{})
	for _, path := range []string{"/api/security/summary", "/api/security/computers/agent:one"} {
		if rec := do(h, "GET", path, "", bearer); rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s: код %d, хочу 503", path, rec.Code)
		}
	}
}
