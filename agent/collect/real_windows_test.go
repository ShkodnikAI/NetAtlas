// Реальный сбор на windows-latest (NR-006): только чтение, без сети,
// без прав администратора. На других ОС пропускается.
package collect

import (
	"context"
	"runtime"
	"testing"
	"time"
)

func TestRealCollectorsOnWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("реальные сборщики PowerShell — только на Windows")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	cs := DefaultCollectors(NewPowerShellRunner())
	rep := BuildReport(ctx, "ci-runner", cs, time.Now())
	if rep.InventorySchemaVersion != SchemaVersion || rep.Hostname != "ci-runner" {
		t.Fatalf("шапка отчёта: %+v", rep)
	}
	// Ни один сборщик не должен упасть целиком на раннере.
	if len(rep.CollectorErrors) != 0 {
		t.Fatalf("ошибки сборщиков: %v", rep.CollectorErrors)
	}
	// Обязательные поля реальной машины.
	if rep.OS == nil || rep.OS.Caption == "" || rep.OS.Architecture == "" {
		t.Fatalf("ОС не собрана: %+v", rep.OS)
	}
	if rep.Hardware == nil || len(rep.Hardware.CPUs) == 0 || rep.Hardware.TotalPhysicalMemory == "" {
		t.Fatalf("железо не собрано: %+v", rep.Hardware)
	}
	if len(rep.Network) == 0 {
		t.Fatal("сетевые адаптеры не собраны")
	}
	if len(rep.Drivers) == 0 {
		t.Fatal("драйверы не собраны")
	}
	if len(rep.Programs) == 0 {
		t.Fatal("программы не собраны")
	}
	if rep.Disks == nil || len(rep.Disks.Volumes) == 0 {
		t.Fatalf("тома не собраны: %+v", rep.Disks)
	}
}
