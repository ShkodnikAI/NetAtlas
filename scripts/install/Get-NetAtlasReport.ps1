<#
.SYNOPSIS
    Текстовый отчёт для аудитора без секретов (NR-028).
.DESCRIPTION
    Собирает состояние сервера NetAtlas: версия, Windows, права,
    задача и порт, /api/config, /api/audit/verify, число устройств,
    связей и агентов, последние 30 строк журнала сервера (с
    маскированием секретов), подсети. Печатает отчёт и сохраняет его
    в logs\report-<время>.txt. Секреты (токен владельца, пароли,
    Bearer) маскируются; сам токен в отчёт не попадает.
.EXAMPLE
    .\Get-NetAtlasReport.ps1
#>
[CmdletBinding()]
param(
    [string]$Dir = 'C:\NetAtlas',
    # Явный путь сохранения (по умолчанию logs\report-<время>.txt).
    [string]$OutFile
)

$ErrorActionPreference = 'Stop'
$commonPath = Join-Path $PSScriptRoot 'NetAtlas.Common.psm1'
if (-not (Test-Path -LiteralPath $commonPath)) {
    Write-Host 'ОШИБКА: рядом со скриптом нет NetAtlas.Common.psm1 (запускайте из распакованного архива или из scripts/install)'
    exit 1
}
Import-Module $commonPath -Force -DisableNameChecking

try {
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add('============ ОТЧЁТ NETATLAS ДЛЯ АУДИТОРА ============')
    $lines.Add(('Время: {0}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')))

    # Версия и дата сборки.
    $versionFile = Join-Path $Dir 'app\VERSION.txt'
    if (Test-Path -LiteralPath $versionFile) {
        $v = (Get-Content -LiteralPath $versionFile -TotalCount 1).Trim()
        $d = (Get-Content -LiteralPath $versionFile | Select-Object -Skip 1 -First 1)
        $lines.Add(('Версия NetAtlas: {0} (сборка {1})' -f $v, $d))
    } else {
        $lines.Add('Версия NetAtlas: неизвестна (нет app\VERSION.txt)')
    }

    # Windows, права.
    $os = Get-CimInstance Win32_OperatingSystem
    $lines.Add(('Windows: {0} (сборка {1})' -f $os.Caption, $os.BuildNumber))
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $isAdmin = (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $lines.Add(('Права администратора: {0}' -f $(if ($isAdmin) { 'да' } else { 'нет' })))

    # Задача планировщика и порт.
    try {
        $task = Get-ScheduledTask -TaskName 'NetAtlasServer' -ErrorAction Stop
        $info = $task | Get-ScheduledTaskInfo
        $lines.Add(('Задача NetAtlasServer: {0}, последний запуск: {1}, результат: {2}' -f $task.State, $info.LastRunTime, $info.LastTaskResult))
    } catch {
        $lines.Add('Задача NetAtlasServer: не установлена (или запуск с -NoService)')
    }
    $portOk = $false
    try {
        $null = Get-NetTCPConnection -LocalPort 8484 -State Listen -ErrorAction Stop
        $portOk = $true
    } catch { }
    $lines.Add(('Порт 8484 слушается: {0}' -f $(if ($portOk) { 'да' } else { 'нет' })))

    # API: конфигурация и цепочка аудита (без токена: /api/config открыт).
    try {
        $cfg = Invoke-NaApi -Uri 'http://127.0.0.1:8484/api/config' -TimeoutSec 10
        $lines.Add(('Ответ /api/config: подсети=[{0}], snmp={1}, audit_ok={2}' -f (($cfg.subnets) -join ', '), $cfg.snmp, $cfg.audit_ok))
    } catch {
        $lines.Add(('Ответ /api/config: сервер не отвечает ({0})' -f $_.Exception.Message))
    }
    try {
        $token = Read-OwnerToken -Dir $Dir
        $ver = Invoke-NaApi -Uri 'http://127.0.0.1:8484/api/audit/verify' -Token $token -TimeoutSec 10
        $lines.Add(('Цепочка аудита (/api/audit/verify): ok={0}{1}' -f $ver.ok, $(if ($ver.error) { ', ' + $ver.error } else { '' })))

        # Числа: устройства, связи, агенты.
        $devs = Invoke-NaApi -Uri 'http://127.0.0.1:8484/api/devices' -Token $token -TimeoutSec 10
        $lines.Add(('Устройств в базе: {0}' -f @($devs).Count))
        try {
            $topo = Invoke-NaApi -Uri 'http://127.0.0.1:8484/api/topology' -Token $token -TimeoutSec 10
            $lines.Add(('Связей: {0}' -f @($topo.links).Count))
        } catch { }
        try {
            $agents = Invoke-NaApi -Uri 'http://127.0.0.1:8484/api/agents' -Token $token -TimeoutSec 10
            $lines.Add(('Агентов: {0}' -f @($agents.agents).Count))
        } catch { }
    } catch {
        $lines.Add(('Разделы с токеном пропущены: {0}' -f $_.Exception.Message))
    }

    # Последние 30 строк журнала сервера (с маскированием).
    $logDir = Join-Path $Dir 'logs'
    $latest = $null
    if (Test-Path -LiteralPath $logDir) {
        $latest = Get-ChildItem -LiteralPath $logDir -Filter 'server-err-*.log' -File -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending | Select-Object -First 1
    }
    if ($latest) {
        $lines.Add(('---- последние 30 строк {0} (маскировано) ----' -f $latest.Name))
        $tail = @(Get-Content -LiteralPath $latest.FullName -Tail 30 -ErrorAction SilentlyContinue)
        foreach ($l in $tail) { $lines.Add((Get-MaskedText -Text $l)) }
    } else {
        $lines.Add('Журнал сервера: не найден (сервер не запускался)')
    }

    # Сохранение и печать.
    if (-not $OutFile) {
        $OutFile = Join-Path $logDir ('report-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.txt')
    }
    if (-not (Test-Path -LiteralPath $logDir)) {
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    }
    [IO.File]::WriteAllLines($OutFile, $lines)
    foreach ($l in $lines) { Write-Host $l }
    Write-Host ''
    Write-Ok ("отчёт сохранён: {0} — отправьте аудитору файл или текст" -f $OutFile)
}
catch {
    Write-Fail $_.Exception.Message
    exit 1
}
