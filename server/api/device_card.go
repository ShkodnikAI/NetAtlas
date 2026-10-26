// Полная карточка устройства (NR-033 п.2a): недостающие поля
// добавляются в ответ GET /api/devices/{id} — один запрос собирает
// данные из уже существующих источников (агенты, инвентарь,
// проверки безопасности, правила, оповещения, журнал аудита).
// Новых зависимостей нет; данные отдаются как есть, интерфейс
// вставляет их через textContent.

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/ShkodnikAI/NetAtlas/agent/checks"
	"github.com/ShkodnikAI/NetAtlas/agent/collect"
	"github.com/ShkodnikAI/NetAtlas/rules"
	"github.com/ShkodnikAI/NetAtlas/rules/security"
	"github.com/ShkodnikAI/NetAtlas/server/store"
)

// agentBrief — связанный агент устройства.
type agentBrief struct {
	ID       string `json:"id"`
	Hostname string `json:"hostname,omitempty"`
}

// cardSecurityFinding — находка правил безопасности (как на экране
// «Безопасность», без весов).
type cardSecurityFinding struct {
	RuleID   string `json:"rule_id"`
	Severity string `json:"severity"`
	Fact     string `json:"fact"`
	Source   string `json:"source"`
	Advice   string `json:"advice"`
	Basis    string `json:"basis"`
	BasisURL string `json:"basis_url,omitempty"`
}

// deviceCardResponse — расширенная карточка: базовые поля
// store.DeviceInfo плюс сведения агента, безопасности, качества,
// оповещений и истории. Все поля необязательные: списки устройств
// используют GET /api/devices без изменений.
type deviceCardResponse struct {
	store.DeviceInfo
	// Агент и инвентарь (ОС, железо, ПО, диски, обновления).
	Agent          *agentBrief     `json:"agent,omitempty"`
	AgentInventory *collect.Report `json:"agent_inventory,omitempty"`
	InventoryAt    string          `json:"inventory_at,omitempty"`
	// Привязанный пользователь: последний замеченный аккаунт
	// активности агента; пусто — сбор выключен или записей нет.
	User string `json:"user,omitempty"`
	// Открытые порты и службы — из проверки портов агента.
	Ports []portEntry `json:"ports,omitempty"`
	// «Найдено правилами»: безопасность и качество сети.
	Security []cardSecurityFinding `json:"security,omitempty"`
	Quality  []rules.Finding       `json:"quality,omitempty"`
	// Открытые оповещения устройства и история изменений.
	Alerts  []store.OpenAlert    `json:"alerts,omitempty"`
	History []store.HistoryEntry `json:"history,omitempty"`
}

// SNMP: в текущей схеме данные SNMP не сохраняются на устройстве
// (сканер использует их только для построения связей), поэтому поле
// не отдаётся. Предположение зафиксировано в отчёте наряда NR-033.

// enrichDeviceCard — заполнение deviceCardResponse общими
// источниками; вызывается из handleDevice (api.go).
func (a *API) enrichDeviceCard(r *http.Request, info store.DeviceInfo) deviceCardResponse {
	resp := deviceCardResponse{DeviceInfo: info}
	ctx := r.Context()

	// Агент по MAC устройства (агенты пишут MAC своих адаптеров при
	// регистрации).
	agentsByMAC, err := a.store.AgentsByMAC(ctx)
	if err == nil {
		if ref, ok := agentsByMAC[info.ID]; ok {
			resp.Agent = &agentBrief{ID: ref.ID, Hostname: ref.Hostname}
			// Инвентарь: последняя порция (ОС, железо, ПО, диски).
			if inv, invErr := a.store.LatestInventory(ctx, ref.ID); invErr == nil {
				resp.InventoryAt = inv.CollectedAt.Format(time.RFC3339)
				resp.AgentInventory = reportOf(inv)
				// Качество сети: правила по метрикам.
				if a.rules != nil {
					if rep := reportOf(inv); rep != nil {
						resp.Quality = []rules.Finding{}
						for _, f := range a.rules.Evaluate(rep, time.Now()) {
							if strings.HasPrefix(f.Source, "metrics.") {
								resp.Quality = append(resp.Quality, f)
							}
						}
					}
				}
			}
			// Безопасность: те же находки, что у экрана
			// «Безопасность», и открытые порты из проверки портов.
			if a.rules != nil {
				sec := security.NewEngine(a.rules)
				res, known := a.agentSecurity(r, sec, ref.ID, ref.Hostname, time.Now())
				if known {
					resp.Security = []cardSecurityFinding{}
					for _, f := range res.Findings {
						resp.Security = append(resp.Security, cardSecurityFinding{
							RuleID:   f.RuleID,
							Severity: f.Severity,
							Fact:     f.Fact,
							Source:   f.Source,
							Advice:   f.Advice,
							Basis:    f.Basis,
							BasisURL: f.BasisURL,
						})
					}
				}
				resp.Ports = a.agentListeningPorts(ctx, ref.ID)
			}
			// Привязанный пользователь.
			if account, accErr := a.store.LastActivityAccount(ctx, ref.ID); accErr == nil {
				resp.User = account
			}
		}
	}

	// Открытые оповещения устройства (NR-005).
	if alerts, err := a.store.OpenAlertsByDevice(ctx, info.ID); err == nil {
		resp.Alerts = alerts
	}
	// История изменений: последние записи журнала аудита по цели.
	if history, err := a.store.AuditForTarget(ctx, info.ID, 50); err == nil {
		resp.History = history
	}
	return resp
}

// agentListeningPorts — слушающие порты из последнего отчёта
// проверок безопасности агента.
func (a *API) agentListeningPorts(ctx context.Context, agentID string) []portEntry {
	sr, err := a.store.LatestSecurity(ctx, agentID)
	if err != nil {
		return nil
	}
	var env struct {
		Results []checks.Result `json:"results"`
	}
	if err := json.Unmarshal([]byte(sr.JSON), &env); err != nil {
		return nil
	}
	ports := []portEntry{}
	for _, chk := range env.Results {
		if chk.ID != checks.CheckPorts || chk.Status != checks.StatusPass || len(chk.Data) == 0 {
			continue
		}
		var data struct {
			Ports []portEntry `json:"ports"`
		}
		if err := json.Unmarshal(chk.Data, &data); err == nil {
			ports = append(ports, data.Ports...)
		}
	}
	return ports
}
