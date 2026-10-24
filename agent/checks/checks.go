// Package checks — проверки безопасности на агенте (NR-010):
// встроенные сценарии PowerShell только для чтения и разбор их
// вывода. Ничего не включает, не отключает, не пишет в реестр и
// не запускает активных проб — это проверяется отдельным тестом
// (запрещённые глаголы в сценариях ломают сборку тестов).
//
// Три состояния проверки, и «не определено» не равно «безопасно»:
//
//	pass    — проверка выполнена, замечаний нет;
//	fail    — проверка выполнена, найдено замечание;
//	unknown — проверка не состоялась (нет командлета, отказ в
//	          доступе, пустой или неразборчивый вывод).
package checks

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// Статусы проверки.
const (
	StatusPass    = "pass"
	StatusFail    = "fail"
	StatusUnknown = "unknown"
)

// SchemaVersion — версия схемы отчёта проверок; идёт в конверте
// отправления на сервер.
const SchemaVersion = 1

// Имена проверок (идентификаторы в отчёте и в правилах оценки).
const (
	CheckSMBv1     = "smbv1"
	CheckBitLocker = "bitlocker"
	CheckRDPNLA    = "rdp_nla"
	CheckFirewall  = "firewall"
	CheckPorts     = "ports"
	CheckDefender  = "defender"
)

// MaxDetail — предел текста detail (сервер отклоняет длиннее).
const MaxDetail = 2000

// Result — итог одной проверки.
type Result struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
	// Data — дополнительные данные проверки (например, список
	// слушающих портов). Сохраняется как есть.
	Data json.RawMessage `json:"data,omitempty"`
}

// Checker — одна проверка.
type Checker interface {
	Name() string
	Run(ctx context.Context) (Result, error)
}

// Report — отчёт проверок (payload конверта).
type Report struct {
	SecuritySchemaVersion int      `json:"security_schema_version"`
	CollectedAt           string   `json:"collected_at"`
	Results               []Result `json:"results"`
}

// BuildReport собирает отчёт проверок: каждая проверка независима,
// ошибка одной не роняет отчёт — она даёт unknown с причиной в
// detail. Порядок результатов — порядок проверок в списке.
func BuildReport(ctx context.Context, hostname string, cs []Checker, now time.Time) Report {
	_ = hostname // имя хоста в отчёте не нужно: сервер знает агента по сертификату
	rep := Report{
		SecuritySchemaVersion: SchemaVersion,
		CollectedAt:           now.UTC().Format(time.RFC3339),
		Results:               make([]Result, 0, len(cs)),
	}
	for _, c := range cs {
		res, err := c.Run(ctx)
		switch {
		case err != nil:
			detail := err.Error()
			if len(detail) > MaxDetail {
				detail = detail[:MaxDetail]
			}
			res = Result{ID: c.Name(), Status: StatusUnknown, Detail: detail}
		case res.Status != StatusPass && res.Status != StatusFail && res.Status != StatusUnknown:
			res = Result{ID: c.Name(), Status: StatusUnknown, Detail: fmt.Sprintf("недопустимый статус %q", res.Status)}
		}
		rep.Results = append(rep.Results, res)
	}
	return rep
}

// DefaultChecks — набор проверок по наряду. Runner подменяется в
// тестах; в работе — PowerShell.
func DefaultChecks(run ScriptRunner) []Checker {
	return []Checker{
		&scriptCheck{run: run, name: CheckSMBv1, script: "smbv1", parse: parseSMBv1},
		&scriptCheck{run: run, name: CheckBitLocker, script: "bitlocker", parse: parseBitLocker},
		&scriptCheck{run: run, name: CheckRDPNLA, script: "rdp_nla", parse: parseRDPNLA},
		&scriptCheck{run: run, name: CheckFirewall, script: "firewall", parse: parseFirewall},
		&scriptCheck{run: run, name: CheckPorts, script: "ports", parse: parsePorts},
		&scriptCheck{run: run, name: CheckDefender, script: "defender", parse: parseDefender},
	}
}

// scriptCheck — общий каркас: имя встроенного сценария и парсер
// его вывода. Парсер сам решает pass/fail/unknown; ошибка разбора —
// unknown (не «безопасно»).
type scriptCheck struct {
	run    ScriptRunner
	name   string
	script string
	parse  func(json.RawMessage) (Result, error)
}

func (c *scriptCheck) Name() string { return c.name }

func (c *scriptCheck) Run(ctx context.Context) (Result, error) {
	raw, err := c.run.Run(ctx, c.script)
	if err != nil {
		return Result{}, err
	}
	res, err := c.parse(raw)
	if err != nil {
		return Result{ID: c.name, Status: StatusUnknown,
			Detail: fmt.Sprintf("разбор вывода: %v", err)}, nil
	}
	res.ID = c.name
	if len(res.Detail) > MaxDetail {
		res.Detail = res.Detail[:MaxDetail]
	}
	return res, nil
}
