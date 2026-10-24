// Package checks — серверный запуск статических проверок скриптов
// PowerShell (PSScriptAnalyzer через pwsh). Проверка только
// анализирует текст: скрипт не исполняется ни на сервере, ни где-то
// ещё. Если pwsh или PSScriptAnalyzer недоступны, стадия «проверен»
// ставится только записью результата, пришедшей со стенда (NR-026),
// или ручной отметкой с комментарием — это решает вызывающий код.
package checks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// ErrUnavailable — pwsh нет в PATH или PSScriptAnalyzer не найден:
// локальная проверка невозможна, сервер честно отвечает отказом.
var ErrUnavailable = errors.New("checks: pwsh с PSScriptAnalyzer недоступен")

// analyzerTimeout — предел одной статической проверки.
const analyzerTimeout = 2 * time.Minute

// Finding — одно замечание анализатора.
type Finding struct {
	RuleName string `json:"rule_name"`
	Severity string `json:"severity"`
	Line     int    `json:"line"`
	Column   int    `json:"column"`
	Message  string `json:"message"`
}

// Report — итог статической проверки. OK — замечаний уровня Error нет.
type Report struct {
	OK       bool      `json:"ok"`
	Tool     string    `json:"tool"`
	Findings []Finding `json:"findings"`
}

// Runner — запуск анализатора над файлом скрипта (подменяется в
// тестах; рабочая реализация вызывает pwsh).
type Runner interface {
	AnalyzeFile(ctx context.Context, path string) ([]Finding, error)
}

// RunnerFunc — адаптер функции.
type RunnerFunc func(ctx context.Context, path string) ([]Finding, error)

// AnalyzeFile вызывает f.
func (f RunnerFunc) AnalyzeFile(ctx context.Context, path string) ([]Finding, error) {
	return f(ctx, path)
}

// Available — есть ли pwsh в PATH. Достаточное условие попытки
// локальной проверки; отсутствие PSScriptAnalyzer проявится ошибкой
// при запуске.
func Available() bool {
	_, err := exec.LookPath("pwsh")
	return err == nil
}

// Analyze — статическая проверка содержимого скрипта раннером r.
// Содержимое пишется во временный файл (без изменения имени-шаблона:
// анализ работает с текстом), файл удаляется после прогона.
func Analyze(ctx context.Context, content string, r Runner) (Report, error) {
	if r == nil {
		r = DefaultRunner{}
	}
	dir, err := os.MkdirTemp("", "netatlas-check-")
	if err != nil {
		return Report{}, fmt.Errorf("checks: временный каталог: %w", err)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "script.ps1")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		return Report{}, fmt.Errorf("checks: временный файл: %w", err)
	}
	findings, err := r.AnalyzeFile(ctx, path)
	if err != nil {
		return Report{}, err
	}
	ok := true
	for _, f := range findings {
		if strings.EqualFold(f.Severity, "error") {
			ok = false
		}
	}
	return Report{OK: ok, Tool: "PSScriptAnalyzer", Findings: findings}, nil
}

// DefaultRunner — запуск pwsh с Invoke-ScriptAnalyzer. Вывод — JSON
// массив записей. Отсутствие pwsh или модуля — ErrUnavailable.
type DefaultRunner struct{}

// AnalyzeFile вызывает pwsh. Команда не содержит содержимого скрипта:
// путь временного файла только.
func (DefaultRunner) AnalyzeFile(ctx context.Context, path string) ([]Finding, error) {
	cctx, cancel := context.WithTimeout(ctx, analyzerTimeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, "pwsh", "-NoProfile", "-NonInteractive", "-Command",
		`Invoke-ScriptAnalyzer -Path $args[0] | ConvertTo-Json -Compress -Depth 4`, path)
	out, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) && strings.Contains(strings.ToLower(string(ee.Stderr)), "invoke-scriptanalyzer") {
			return nil, ErrUnavailable
		}
		if execErr := new(exec.Error); errors.As(err, &execErr) {
			return nil, ErrUnavailable
		}
		return nil, fmt.Errorf("checks: pwsh: %w", err)
	}
	return parseAnalyzerJSON(out)
}

// parseAnalyzerJSON — разбор вывода ConvertTo-Json: массив записей
// или одна запись; пустой вывод — замечаний нет.
func parseAnalyzerJSON(out []byte) ([]Finding, error) {
	trimmed := strings.TrimSpace(string(out))
	if trimmed == "" {
		return nil, nil
	}
	var raw []struct {
		RuleName   string `json:"RuleName"`
		Severity   string `json:"Severity"`
		Line       int    `json:"Line"`
		Column     int    `json:"Column"`
		Message    string `json:"Message"`
		ScriptPath string `json:"ScriptPath"`
	}
	if strings.HasPrefix(trimmed, "[") {
		if err := json.Unmarshal(out, &raw); err != nil {
			return nil, fmt.Errorf("checks: вывод анализатора: %w", err)
		}
	} else {
		var one struct {
			RuleName string `json:"RuleName"`
			Severity string `json:"Severity"`
			Line     int    `json:"Line"`
			Column   int    `json:"Column"`
			Message  string `json:"Message"`
		}
		if err := json.Unmarshal(out, &one); err != nil {
			return nil, fmt.Errorf("checks: вывод анализатора: %w", err)
		}
		raw = append(raw, struct {
			RuleName   string `json:"RuleName"`
			Severity   string `json:"Severity"`
			Line       int    `json:"Line"`
			Column     int    `json:"Column"`
			Message    string `json:"Message"`
			ScriptPath string `json:"ScriptPath"`
		}{one.RuleName, one.Severity, one.Line, one.Column, one.Message, ""})
	}
	findings := make([]Finding, 0, len(raw))
	for _, r := range raw {
		findings = append(findings, Finding{
			RuleName: r.RuleName, Severity: r.Severity, Line: r.Line, Column: r.Column, Message: r.Message,
		})
	}
	return findings, nil
}
