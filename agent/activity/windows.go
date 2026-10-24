//go:build windows

// Мгновенные снимки для сбора активности (только чтение):
// имя процесса активного окна (GetForegroundWindow → имя exe, без
// заголовка), простой ввода (GetLastInputInfo — только время),
// учётная запись и исключения-администраторы, домены из DNS-кэша
// (Get-DnsClientCache — только имена). Функции ввода с клавиатуры,
// снимки экрана и буфер обмена здесь отсутствуют.
package activity

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Source — источник снимков Windows: Win32 и DNS-кэш.
type Source struct {
	lastDNS time.Time
	dns     []string
}

// NewSource — сборщик снимков (Windows).
func NewSource() *Source { return &Source{} }

// Snap делает снимок. Ошибка снимка не блокирует агрегацию: поле
// останется пустым (инвариант: если источник нельзя получить без
// запрещённых данных — поле отсутствует).
func (c *Source) Snap(ctx context.Context) Snapshot {
	return Snapshot{
		Process: foregroundProcess(),
		IdleMS:  idleMillis(),
		Domains: c.dnsDomains(ctx),
	}
}

// foregroundProcess — имя exe активного окна. Заголовок окна
// сознательно не читается (инвариант наряда).
func foregroundProcess() string {
	user32 := windows.NewLazySystemDLL("user32.dll")
	getForeground := user32.NewProc("GetForegroundWindow")
	getPID := user32.NewProc("GetWindowThreadProcessId")
	hw, _, _ := getForeground.Call()
	if hw == 0 {
		return ""
	}
	var pid uint32
	getPID.Call(hw, uintptr(unsafe.Pointer(&pid)))
	if pid == 0 {
		return ""
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h)
	var name [syscall.MAX_PATH]uint16
	size := uint32(len(name))
	if err := windows.QueryFullProcessImageName(h, 0, &name[0], &size); err != nil {
		return ""
	}
	return windows.UTF16ToString(name[:size])
}

// idleMillis — миллисекунды с последнего ввода (GetLastInputInfo —
// только время, не события). DWTime — GetTickCount-метка последнего
// ввода; разница с текущим GetTickCount64 — время простоя (обёртка
// 32-битного счётчика: при переполнении разница остаётся верной в
// пределах 49 дней без ввода, что за пределами смысла «простоя»).
func idleMillis() int64 {
	user32 := windows.NewLazySystemDLL("user32.dll")
	getLastInput := user32.NewProc("GetLastInputInfo")
	var li struct {
		CBSize uint32
		DWTime uint32
	}
	li.CBSize = uint32(unsafe.Sizeof(li))
	r, _, _ := getLastInput.Call(uintptr(unsafe.Pointer(&li)))
	if r == 0 {
		return 0
	}
	tick := tickMillis()
	return int64(tick) - int64(li.DWTime)
}

// tickMillis — текущее значение счётчика аптайма (GetTickCount64,
// усечённое до 32 бит — та же шкала, что DWTime).
func tickMillis() uint32 {
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	p := kernel32.NewProc("GetTickCount64")
	v, _, _ := p.Call()
	return uint32(v)
}

// dnsDomains — имена доменов из DNS-кэша клиента (Get-DnsClientCache):
// только поле Entry (имя), без путей и содержимого. Опрос не чаще
// DNSInterval.
func (c *Source) dnsDomains(ctx context.Context) []string {
	if !c.lastDNS.IsZero() && time.Since(c.lastDNS) < DNSInterval {
		return c.dns
	}
	c.lastDNS = time.Now()
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
		`Get-DnsClientCache | Select-Object -ExpandProperty Entry -Unique | ConvertTo-Json -Compress`).Output()
	if err != nil {
		c.dns = nil // источник недоступен: поле отсутствует
		return nil
	}
	var hosts []string
	if json.Unmarshal(out, &hosts) != nil {
		var one string
		if json.Unmarshal(out, &one) == nil {
			hosts = []string{one}
		} else {
			c.dns = nil
			return nil
		}
	}
	c.dns = hosts
	return hosts
}

// Account — текущая учётная запись, признак администратора и члены
// группы администраторов (по SID S-1-5-32-544, независимо от языка
// Windows). Один вызов PowerShell, только чтение.
func Account(ctx context.Context) (AccountInfo, error) {
	var info AccountInfo
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", `
$wi = [Security.Principal.WindowsIdentity]::GetCurrent()
$pr = New-Object Security.Principal.WindowsPrincipal($wi)
$admins = @()
try {
    $g = Get-LocalGroup -SID S-1-5-32-544 -ErrorAction Stop
    $admins = Get-LocalGroupMember -Group $g -ErrorAction Stop | ForEach-Object { $_.Name }
} catch { $admins = @() }
[pscustomobject]@{ account = $wi.Name; is_admin = $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator); admins = $admins } | ConvertTo-Json -Compress`).Output()
	if err != nil {
		return info, fmt.Errorf("activity: учётная запись: %w", err)
	}
	if err := json.Unmarshal(out, &info); err != nil {
		return info, fmt.Errorf("activity: разбор учётной записи: %w", err)
	}
	info.Account = strings.TrimSpace(info.Account)
	for i, a := range info.Admins {
		info.Admins[i] = strings.TrimSpace(a)
	}
	return info, nil
}
