// Тесты агентской части хранилища (NR-024): регистрация, состояния,
// инвентарь, привязка к карте по MAC.
package store

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

// Регистрация агента: запись создана, MAC нормализованы, аудит написан.
func TestUpsertAgentEnrolls(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()

	if err := s.UpsertAgent(ctx, "agent:abc", "pc1", "12345",
		[]string{"AA-BB-CC-DD-EE-01", "aabb.ccdd.ee02", "AA-BB-CC-DD-EE-01"}, "owner"); err != nil {
		t.Fatalf("UpsertAgent: %v", err)
	}
	a, err := s.AgentByID(ctx, "agent:abc")
	if err != nil {
		t.Fatalf("AgentByID: %v", err)
	}
	if a.Hostname != "pc1" || a.CertSerial != "12345" || a.Status != "active" {
		t.Fatalf("карточка агента: %+v", a)
	}
	if len(a.MACList) != 2 || a.MACList[0] != "aa:bb:cc:dd:ee:01" || a.MACList[1] != "aa:bb:cc:dd:ee:02" {
		t.Fatalf("mac_list = %v, хочу нормализованные и без повтора", a.MACList)
	}
	if a.EnrolledAt.IsZero() {
		t.Fatal("enrolled_at пуст")
	}
	entries, err := auditListAll(s)
	if err != nil {
		t.Fatalf("журнал: %v", err)
	}
	found := false
	for _, e := range entries {
		if e.action == "agent_enroll" && e.target == "agent:abc" {
			found = true
		}
	}
	if !found {
		t.Fatal("нет записи agent_enroll в журнале")
	}
}

// Идентификатор агента обязан иметь префикс agent: — это схема
// личности из сертификата.
func TestUpsertAgentRejectsBadID(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	if err := s.UpsertAgent(ctx, "host-1", "pc1", "1", nil, "owner"); err == nil {
		t.Fatal("id без префикса agent: принят")
	}
}

// Повторная регистрация того же CN обновляет данные и возвращает
// агента в active (перевыпуск сертификата).
func TestUpsertAgentReenrollReactivates(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	if err := s.UpsertAgent(ctx, "agent:abc", "pc1", "111", []string{"aa:bb:cc:dd:ee:01"}, "owner"); err != nil {
		t.Fatalf("UpsertAgent: %v", err)
	}
	if err := s.RevokeAgent(ctx, "agent:abc", "owner"); err != nil {
		t.Fatalf("RevokeAgent: %v", err)
	}
	if err := s.UpsertAgent(ctx, "agent:abc", "pc1-new", "222", []string{"aa:bb:cc:dd:ee:99"}, "owner"); err != nil {
		t.Fatalf("повторный UpsertAgent: %v", err)
	}
	a, err := s.AgentByID(ctx, "agent:abc")
	if err != nil {
		t.Fatalf("AgentByID: %v", err)
	}
	if a.Status != "active" || a.CertSerial != "222" || a.Hostname != "pc1-new" {
		t.Fatalf("после перевыпуска: %+v", a)
	}
	if len(a.MACList) != 1 || a.MACList[0] != "aa:bb:cc:dd:ee:99" {
		t.Fatalf("mac_list после перевыпуска = %v", a.MACList)
	}
}

// Выход на связь обновляет last_seen; неизвестный агент — ErrNotFound.
func TestAgentCheckin(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	if err := s.AgentCheckin(ctx, "agent:ghost"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("чужой checkin: %v, хочу ErrNotFound", err)
	}
	if err := s.UpsertAgent(ctx, "agent:abc", "pc1", "1", nil, "owner"); err != nil {
		t.Fatalf("UpsertAgent: %v", err)
	}
	if err := s.AgentCheckin(ctx, "agent:abc"); err != nil {
		t.Fatalf("checkin: %v", err)
	}
	a, err := s.AgentByID(ctx, "agent:abc")
	if err != nil {
		t.Fatalf("AgentByID: %v", err)
	}
	if a.LastSeen.IsZero() {
		t.Fatal("last_seen не обновлён")
	}
}

// Инвентарь сохраняется с аудитом; агент-призрак отвергается
// внешним ключом.
func TestSaveInventoryAndFK(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	if err := s.SaveInventory(ctx, "agent:ghost", "osinfo", 1, time.Now(), []byte(`{}`)); err == nil {
		t.Fatal("инвентарь неизвестного агента принят (FK молчит)")
	}
	if err := s.UpsertAgent(ctx, "agent:abc", "pc1", "1", nil, "owner"); err != nil {
		t.Fatalf("UpsertAgent: %v", err)
	}
	raw := []byte(`{"kind":"osinfo","schema_ver":2,"collected_at":"2026-10-24T10:00:00Z","payload":{"os":"win"}}`)
	if err := s.SaveInventory(ctx, "agent:abc", "osinfo", 2, time.Now(), raw); err != nil {
		t.Fatalf("SaveInventory: %v", err)
	}
	var got string
	if err := s.DB().QueryRow(`SELECT json FROM agent_inventory WHERE agent_id = 'agent:abc'`).Scan(&got); err != nil {
		t.Fatalf("чтение инвентаря: %v", err)
	}
	if got != string(raw) {
		t.Fatalf("тело инвентаря исказилось: %q", got)
	}
	entries, err := auditListAll(s)
	if err != nil {
		t.Fatalf("журнал: %v", err)
	}
	found := false
	for _, e := range entries {
		if e.action == "agent_inventory" && e.target == "agent:abc" {
			found = true
		}
	}
	if !found {
		t.Fatal("нет записи agent_inventory в журнале")
	}
}

// Отзыв: активный → revoked (с аудитом), повторный отзыв —
// ErrAgentRevoked, чужой — ErrNotFound.
func TestRevokeAgentStates(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	if err := s.RevokeAgent(ctx, "agent:ghost", "owner"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("чужой отзыв: %v, хочу ErrNotFound", err)
	}
	if err := s.UpsertAgent(ctx, "agent:abc", "pc1", "1", nil, "owner"); err != nil {
		t.Fatalf("UpsertAgent: %v", err)
	}
	if err := s.RevokeAgent(ctx, "agent:abc", "owner"); err != nil {
		t.Fatalf("RevokeAgent: %v", err)
	}
	if err := s.RevokeAgent(ctx, "agent:abc", "owner"); !errors.Is(err, ErrAgentRevoked) {
		t.Fatalf("повторный отзыв: %v, хочу ErrAgentRevoked", err)
	}
	revoked, err := s.IsAgentRevoked(ctx, "agent:abc")
	if err != nil || !revoked {
		t.Fatalf("IsAgentRevoked = %v (err %v), хочу true", revoked, err)
	}
	if _, err := s.IsAgentRevoked(ctx, "agent:ghost"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("чужой статус: %v, хочу ErrNotFound", err)
	}
	list, err := s.ListRevokedAgents(ctx)
	if err != nil || len(list) != 1 || list[0] != "agent:abc" {
		t.Fatalf("ListRevokedAgents = %v (err %v)", list, err)
	}
	entries, err := auditListAll(s)
	if err != nil {
		t.Fatalf("журнал: %v", err)
	}
	found := false
	for _, e := range entries {
		if e.action == "agent_revoke" && e.target == "agent:abc" && e.actor == "owner" {
			found = true
		}
	}
	if !found {
		t.Fatal("нет записи agent_revoke в журнале")
	}
}

// Привязка MAC: устройства создаются с классом managed, существующие
// переводятся в managed, ручные поля не затираются, аудит есть.
func TestLinkAgentMACs(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	// Существующее устройство с MAC-идентификатором и ручным именем
	// (владелец подписал найденное сканером устройство).
	mac := "aa:bb:cc:dd:ee:09"
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := s.DB().Exec(`INSERT INTO devices
		(id, kind, class, label, hostname, vendor, ssid, manual, verified, first_seen, last_seen)
		VALUES (?, 'device', 'unknown', 'серверная стойка', '', '', '', 1, 0, ?, ?)`,
		mac, now, now); err != nil {
		t.Fatalf("вставка устройства: %v", err)
	}
	if err := s.UpsertAgent(ctx, "agent:abc", "pc1", "1", nil, "owner"); err != nil {
		t.Fatalf("UpsertAgent: %v", err)
	}
	if err := s.LinkAgentMACs(ctx, "agent:abc", []string{
		"AA-BB-CC-DD-EE-01", "мусор", "aa:bb:cc:dd:ee:01", "AA:BB:CC:DD:EE:09",
	}); err != nil {
		t.Fatalf("LinkAgentMACs: %v", err)
	}
	// Новое устройство создано managed.
	d, err := s.Device(ctx, "aa:bb:cc:dd:ee:01")
	if err != nil {
		t.Fatalf("Device: %v", err)
	}
	if d.Class != "managed" || d.Manual {
		t.Fatalf("новое устройство: класс %q, manual=%v", d.Class, d.Manual)
	}
	// Ручное устройство: класс стал managed, имя не тронуто.
	m, err := s.Device(ctx, mac)
	if err != nil {
		t.Fatalf("Device(manual): %v", err)
	}
	if m.Class != "managed" {
		t.Fatalf("ручное устройство: класс %q, хочу managed", m.Class)
	}
	if !m.Manual {
		t.Fatalf("ручное устройство перестало быть ручным: %+v", m)
	}
	var label string
	if err := s.DB().QueryRow(`SELECT label FROM devices WHERE id = ?`, mac).Scan(&label); err != nil {
		t.Fatalf("label: %v", err)
	}
	if label != "серверная стойка" {
		t.Fatalf("ручное имя затёрто: %q", label)
	}
	entries, err := auditListAll(s)
	if err != nil {
		t.Fatalf("журнал: %v", err)
	}
	found := false
	for _, e := range entries {
		if e.action == "agent_link_macs" && e.target == "agent:abc" {
			var det map[string]any
			if json.Unmarshal([]byte(e.detail), &det) == nil && det["linked"] == float64(2) {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("нет записи agent_link_macs с linked=2 (2 уникальных MAC)")
	}
}

// Список агентов: порядок и поля.
func TestListAgents(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	if err := s.UpsertAgent(ctx, "agent:one", "pc1", "1", nil, "owner"); err != nil {
		t.Fatalf("UpsertAgent one: %v", err)
	}
	if err := s.UpsertAgent(ctx, "agent:two", "pc2", "2", []string{"aa:bb:cc:dd:ee:05"}, "owner"); err != nil {
		t.Fatalf("UpsertAgent two: %v", err)
	}
	agents, err := s.ListAgents(ctx)
	if err != nil {
		t.Fatalf("ListAgents: %v", err)
	}
	if len(agents) != 2 {
		t.Fatalf("агентов = %d, хочу 2", len(agents))
	}
	if agents[0].ID != "agent:two" {
		t.Fatalf("первый в списке = %s, хочу agent:two (новейший)", agents[0].ID)
	}
	for _, a := range agents {
		if a.MACList == nil {
			t.Fatalf("mac_list агента %s — nil, хочу пустой список", a.ID)
		}
	}
}
