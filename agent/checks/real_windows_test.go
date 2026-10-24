// Реальные проверки на windows-latest (NR-010): только чтение, без
// прав администратора, без изменения состояния. На других ОС
// пропускается. Голый раннер — не эталон парка: жёстко проверяется
// только каркас, состояния машин — мягко.
package checks

import (
	"context"
	"encoding/json"
	"runtime"
	"testing"
	"time"
)

func TestRealSecurityChecksOnWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("реальные проверки PowerShell — только на Windows")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	rep := BuildReport(ctx, "ci-runner", DefaultChecks(NewPowerShellRunner()), time.Now())
	if rep.SecuritySchemaVersion != SchemaVersion {
		t.Fatalf("версия схемы: %d", rep.SecuritySchemaVersion)
	}
	// Каркас: все шесть проверок вернули валидный статус.
	want := map[string]bool{
		CheckSMBv1: false, CheckBitLocker: false, CheckRDPNLA: false,
		CheckFirewall: false, CheckPorts: false, CheckDefender: false,
	}
	for _, r := range rep.Results {
		if _, ok := want[r.ID]; !ok {
			t.Fatalf("лишняя проверка %q", r.ID)
		}
		want[r.ID] = true
		if r.Status != StatusPass && r.Status != StatusFail && r.Status != StatusUnknown {
			t.Fatalf("проверка %s: недопустимый статус %q", r.ID, r.Status)
		}
		if r.Status == StatusUnknown {
			t.Logf("проверка %s не определилась: %s", r.ID, r.Detail)
		} else {
			t.Logf("проверка %s: %s (%s)", r.ID, r.Status, r.Detail)
		}
	}
	for id, seen := range want {
		if !seen {
			t.Fatalf("проверки %s нет в отчёте", id)
		}
	}
	// Порты обязаны собраться на любой машине: Get-NetTCPConnection
	// работает без прав администратора.
	for _, r := range rep.Results {
		if r.ID != CheckPorts || r.Status != StatusPass {
			continue
		}
		if r.Data != nil {
			var data struct {
				Ports []PortEntry `json:"ports"`
			}
			if err := json.Unmarshal(r.Data, &data); err != nil {
				t.Fatalf("порты: data: %v", err)
			}
			t.Logf("слушающих портов: %d", len(data.Ports))
		}
	}
}
