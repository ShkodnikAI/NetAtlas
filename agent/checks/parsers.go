// Разбор вывода сценариев в статус проверок. Правило одно: явные
// факты дают pass/fail, всё прочее — unknown («не определено», а не
// «безопасно»). Покрыто фикстурами testdata, включая русскую
// локаль, недоступные командлеты и пустой вывод.
package checks

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// tribool — трёхзначный ответ сценария: да / нет / не определено.
type tribool int

const (
	tbUnknown tribool = iota
	tbTrue
	tbFalse
)

// triOf — строка в трёхзначный ответ; числовые и текстовые формы
// принимаются (сценарии отдают строки PowerShell, фикстуры — JSON).
func triOf(s string) tribool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "true", "1", "да", "on", "включён", "включен":
		return tbTrue
	case "false", "0", "нет", "off", "выключен", "отключён", "отключен":
		return tbFalse
	}
	return tbUnknown
}

// unknownIfEmpty — пустой вывод сценария означает «не определено».
func unknownIfEmpty(raw json.RawMessage, id, why string) (Result, bool) {
	if len(raw) == 0 || strings.TrimSpace(string(raw)) == "" || strings.TrimSpace(string(raw)) == "null" {
		return Result{ID: id, Status: StatusUnknown, Detail: why}, true
	}
	return Result{}, false
}

// parseSMBv1 — EnableSMB1Protocol.
func parseSMBv1(raw json.RawMessage) (Result, error) {
	if u, ok := unknownIfEmpty(raw, CheckSMBv1, "SMBv1: вывод пуст (командлет недоступен)"); ok {
		return u, nil
	}
	var src struct {
		Enabled json.RawMessage `json:"enabled"`
	}
	if err := json.Unmarshal(raw, &src); err != nil {
		return Result{}, err
	}
	switch triOf(asString(src.Enabled)) {
	case tbTrue:
		return Result{ID: CheckSMBv1, Status: StatusFail, Detail: "SMBv1 включён"}, nil
	case tbFalse:
		return Result{ID: CheckSMBv1, Status: StatusPass, Detail: "SMBv1 отключён"}, nil
	default:
		return Result{ID: CheckSMBv1, Status: StatusUnknown, Detail: "SMBv1: значение не определено"}, nil
	}
}

// parseBitLocker — статус защиты томов. Хоть один том без защиты —
// замечание; неизвестные статусы не считаются защищёнными.
func parseBitLocker(raw json.RawMessage) (Result, error) {
	if u, ok := unknownIfEmpty(raw, CheckBitLocker, "BitLocker: вывод пуст (командлет недоступен)"); ok {
		return u, nil
	}
	var src struct {
		Volumes json.RawMessage `json:"volumes"`
	}
	if err := json.Unmarshal(raw, &src); err != nil {
		return Result{}, err
	}
	items, err := arrayFrom(src.Volumes)
	if err != nil {
		return Result{}, err
	}
	if len(items) == 0 {
		return Result{ID: CheckBitLocker, Status: StatusUnknown,
			Detail: "BitLocker: нет данных о томах"}, nil
	}
	var off, unknown []string
	for _, it := range items {
		var v struct {
			MountPoint       json.RawMessage `json:"mountPoint"`
			ProtectionStatus json.RawMessage `json:"protectionStatus"`
		}
		if err := json.Unmarshal(it, &v); err != nil {
			return Result{}, err
		}
		mount := asString(v.MountPoint)
		switch triOf(asString(v.ProtectionStatus)) {
		case tbFalse:
			off = append(off, mount)
		case tbTrue:
			// защищён
		default:
			unknown = append(unknown, mount)
		}
	}
	if len(off) > 0 {
		return Result{ID: CheckBitLocker, Status: StatusFail,
			Detail: "тома без шифрования: " + strings.Join(off, ", ")}, nil
	}
	if len(unknown) > 0 {
		return Result{ID: CheckBitLocker, Status: StatusUnknown,
			Detail: "BitLocker: статус не определён: " + strings.Join(unknown, ", ")}, nil
	}
	return Result{ID: CheckBitLocker, Status: StatusPass, Detail: "все тома защищены"}, nil
}

// parseRDPNLA — RDP включён и требует ли он проверку на уровне сети.
func parseRDPNLA(raw json.RawMessage) (Result, error) {
	if u, ok := unknownIfEmpty(raw, CheckRDPNLA, "RDP: вывод пуст (ключи реестра недоступны)"); ok {
		return u, nil
	}
	var src struct {
		RDPEnabled  json.RawMessage `json:"rdpEnabled"`
		NLARequired json.RawMessage `json:"nlaRequired"`
	}
	if err := json.Unmarshal(raw, &src); err != nil {
		return Result{}, err
	}
	switch triOf(asString(src.RDPEnabled)) {
	case tbFalse:
		return Result{ID: CheckRDPNLA, Status: StatusPass, Detail: "удалённый рабочий стол выключен"}, nil
	case tbTrue:
		switch triOf(asString(src.NLARequired)) {
		case tbTrue:
			return Result{ID: CheckRDPNLA, Status: StatusPass, Detail: "RDP включён, требуется проверка на уровне сети (NLA)"}, nil
		case tbFalse:
			return Result{ID: CheckRDPNLA, Status: StatusFail,
				Detail: "RDP включён без проверки на уровне сети (NLA)"}, nil
		default:
			return Result{ID: CheckRDPNLA, Status: StatusUnknown, Detail: "RDP: состояние NLA не определено"}, nil
		}
	default:
		return Result{ID: CheckRDPNLA, Status: StatusUnknown, Detail: "RDP: состояние не определено"}, nil
	}
}

// parseFirewall — состояние брандмауэра по профилям.
func parseFirewall(raw json.RawMessage) (Result, error) {
	if u, ok := unknownIfEmpty(raw, CheckFirewall, "брандмауэр: вывод пуст (командлет недоступен)"); ok {
		return u, nil
	}
	var src struct {
		Profiles json.RawMessage `json:"profiles"`
	}
	if err := json.Unmarshal(raw, &src); err != nil {
		return Result{}, err
	}
	items, err := arrayFrom(src.Profiles)
	if err != nil {
		return Result{}, err
	}
	if len(items) == 0 {
		return Result{ID: CheckFirewall, Status: StatusUnknown,
			Detail: "брандмауэр: нет данных о профилях"}, nil
	}
	var off, unknown []string
	seen := 0
	for _, it := range items {
		var p struct {
			Profile json.RawMessage `json:"profile"`
			Enabled json.RawMessage `json:"enabled"`
		}
		if err := json.Unmarshal(it, &p); err != nil {
			return Result{}, err
		}
		name := asString(p.Profile)
		if name == "" {
			name = strconv.Itoa(seen)
		}
		seen++
		switch triOf(asString(p.Enabled)) {
		case tbFalse:
			off = append(off, name)
		case tbTrue:
			// включён
		default:
			unknown = append(unknown, name)
		}
	}
	if len(off) > 0 {
		return Result{ID: CheckFirewall, Status: StatusFail,
			Detail: "профиль выключен: " + strings.Join(off, ", ")}, nil
	}
	if len(unknown) > 0 {
		return Result{ID: CheckFirewall, Status: StatusUnknown,
			Detail: "брандмауэр: состояние не определено: " + strings.Join(unknown, ", ")}, nil
	}
	return Result{ID: CheckFirewall, Status: StatusPass, Detail: "все профили включены"}, nil
}

// PortEntry — слушающий порт (каноничный вид данных проверки ports).
type PortEntry struct {
	LocalAddress string `json:"local_address"`
	LocalPort    int    `json:"local_port"`
	Process      string `json:"process,omitempty"`
}

// parsePorts — слушающие порты: данные без суждения (владелец
// смотрит список сам). Пустой список — «нет слушающих портов», это
// состояние машины, а не «не определено»: командлет отработал.
func parsePorts(raw json.RawMessage) (Result, error) {
	if u, ok := unknownIfEmpty(raw, CheckPorts, "порты: вывод пуст (командлет недоступен)"); ok {
		return u, nil
	}
	var src struct {
		Ports json.RawMessage `json:"ports"`
	}
	if err := json.Unmarshal(raw, &src); err != nil {
		return Result{}, err
	}
	items, err := arrayFrom(src.Ports)
	if err != nil {
		return Result{}, err
	}
	out := make([]PortEntry, 0, len(items))
	for _, it := range items {
		var p struct {
			LocalAddress json.RawMessage `json:"localAddress"`
			LocalPort    json.RawMessage `json:"localPort"`
			Process      json.RawMessage `json:"process"`
		}
		if err := json.Unmarshal(it, &p); err != nil {
			return Result{}, err
		}
		port, err := strconv.Atoi(strings.TrimSpace(asString(p.LocalPort)))
		if err != nil {
			continue // запись без порта не появляется в списке
		}
		out = append(out, PortEntry{
			LocalAddress: strings.TrimSpace(asString(p.LocalAddress)),
			LocalPort:    port,
			Process:      strings.TrimSpace(asString(p.Process)),
		})
	}
	// Детерминированный порядок: порт, адрес, процесс.
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.LocalPort != b.LocalPort {
			return a.LocalPort < b.LocalPort
		}
		if a.LocalAddress != b.LocalAddress {
			return a.LocalAddress < b.LocalAddress
		}
		return a.Process < b.Process
	})
	var data json.RawMessage
	if len(out) > 0 {
		raw, err := json.Marshal(map[string]any{"ports": out})
		if err != nil {
			return Result{}, fmt.Errorf("checks: порты: %w", err)
		}
		data = raw
	}
	detail := "нет слушающих портов"
	if len(out) > 0 {
		detail = fmt.Sprintf("слушающих портов: %d", len(out))
	}
	return Result{ID: CheckPorts, Status: StatusPass, Detail: detail, Data: data}, nil
}

// parseDefender — состояние Microsoft Defender.
func parseDefender(raw json.RawMessage) (Result, error) {
	if u, ok := unknownIfEmpty(raw, CheckDefender, "Defender: вывод пуст (командлет недоступен)"); ok {
		return u, nil
	}
	var src struct {
		AntivirusEnabled json.RawMessage `json:"antivirusEnabled"`
		RealtimeEnabled  json.RawMessage `json:"realtimeEnabled"`
	}
	if err := json.Unmarshal(raw, &src); err != nil {
		return Result{}, err
	}
	av := triOf(asString(src.AntivirusEnabled))
	rt := triOf(asString(src.RealtimeEnabled))
	if av == tbFalse {
		// Антивирус выключен целиком (часто — заменён сторонним):
		// факт фиксируется, но суждение остаётся за владельцем.
		return Result{ID: CheckDefender, Status: StatusUnknown,
			Detail: "Defender: антивирусная защита выключена (возможен сторонний антивирус)"}, nil
	}
	switch rt {
	case tbTrue:
		return Result{ID: CheckDefender, Status: StatusPass, Detail: "защита в реальном времени включена"}, nil
	case tbFalse:
		return Result{ID: CheckDefender, Status: StatusFail, Detail: "защита в реальном времени отключена"}, nil
	default:
		return Result{ID: CheckDefender, Status: StatusUnknown, Detail: "Defender: состояние не определено"}, nil
	}
}
