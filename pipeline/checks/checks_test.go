package checks

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// Пустой вывод — замечаний нет, отчёт успешен.
func TestParseEmptyOutput(t *testing.T) {
	findings, err := parseAnalyzerJSON([]byte(""))
	if err != nil || len(findings) != 0 {
		t.Fatalf("пустой вывод: %v, %d замечаний", err, len(findings))
	}
}

// Массив записей разбирается в замечания.
func TestParseArrayOutput(t *testing.T) {
	out := []byte(`[{"RuleName":"PSAvoidUsingWriteHost","Severity":"Warning","Line":3,"Column":1,"Message":"Script uses Write-Host"},{"RuleName":"PSUseApprovedVerbs","Severity":"Error","Line":7,"Column":5,"Message":"Unapproved verb"}]`)
	findings, err := parseAnalyzerJSON(out)
	if err != nil {
		t.Fatalf("массив: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("замечаний %d, хочу 2", len(findings))
	}
	if findings[1].RuleName != "PSUseApprovedVerbs" || findings[1].Line != 7 {
		t.Fatalf("второе замечание разобрано неверно: %+v", findings[1])
	}
}

// Одна запись (не массив) разбирается.
func TestParseSingleRecord(t *testing.T) {
	out := []byte(`{"RuleName":"PSAvoidUsingPlainTextForPassword","Severity":"Warning","Line":1,"Column":9,"Message":"msg"}`)
	findings, err := parseAnalyzerJSON(out)
	if err != nil {
		t.Fatalf("одна запись: %v", err)
	}
	if len(findings) != 1 || findings[0].Severity != "Warning" {
		t.Fatalf("запись разобрана неверно: %+v", findings)
	}
}

// Битый JSON — ошибка разбора, не паника.
func TestParseBrokenJSON(t *testing.T) {
	if _, err := parseAnalyzerJSON([]byte("{не json")); err == nil {
		t.Fatal("битый JSON не отвергнут")
	}
}

// Анализ с фейковым раннером: Warning не роняет отчёт, Error — роняет.
func TestAnalyzeWithFakeRunner(t *testing.T) {
	fake := func(severity string) RunnerFunc {
		return func(_ context.Context, path string) ([]Finding, error) {
			if !strings.HasSuffix(path, "script.ps1") {
				return nil, errors.New("ожидался файл script.ps1")
			}
			return []Finding{{RuleName: "R1", Severity: severity, Line: 1}}, nil
		}
	}
	rep, err := Analyze(context.Background(), "$x = 1", fake("Warning"))
	if err != nil {
		t.Fatalf("warning: %v", err)
	}
	if !rep.OK {
		t.Fatal("warning не должен ронять отчёт")
	}
	rep, err = Analyze(context.Background(), "$x = 1", fake("Error"))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if rep.OK {
		t.Fatal("error должен ронять отчёт")
	}
}

// Ошибка раннера доходит до вызывающего.
func TestAnalyzeRunnerError(t *testing.T) {
	want := errors.New("pwsh пропал")
	_, err := Analyze(context.Background(), "$x = 1", RunnerFunc(func(_ context.Context, _ string) ([]Finding, error) {
		return nil, want
	}))
	if !errors.Is(err, want) {
		t.Fatalf("хочу исходную ошибку, получено %v", err)
	}
}
