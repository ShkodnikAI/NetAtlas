<#
.SYNOPSIS
    Отчёт о состоянии агента для аудитора (NR-029) — запуск на
    целевом ПК.
.DESCRIPTION
    Текстовый отчёт без секретов: статус службы, версия агента,
    адрес сервера (из конфигурации службы), доступность сервера,
    последнее успешное checkin (файл статуса от агента), размер
    очереди неслитых отчётов (каталог spool), последние 20 строк
    журнала исполнения с маскированием. Печатается и сохраняется в
    %TEMP%\netatlas-agent-report-<время>.txt.
.EXAMPLE
    .\Get-AgentReport.ps1
#>
[CmdletBinding()]
param(
    [string]$OutFile
)

$ErrorActionPreference = 'Stop'

function Get-MaskedTextLocal {
    param([AllowEmptyString()][string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $Text }
    $out = $Text
    $out = [regex]::Replace($out, '(?i)bearer\s+[A-Za-z0-9._\-]+', 'Bearer [REDACTED]')
    $out = [regex]::Replace($out, '(?i)\b(password|passwd|pwd|token|secret|authorization)\b(\s*[=:]\s*)\S+', '$1$2[REDACTED]')
    $out = [regex]::Replace($out, '\b[A-Za-z0-9_\-]{43}\b', '[REDACTED]')
    return $out
}

try {
    $agentDir = $(if ($env:NETATLAS_AGENT_DIR) { $env:NETATLAS_AGENT_DIR } else { Join-Path $env:ProgramData 'NetAtlas\agent' })
    # Бинарник агента — тот, из которого ставилась служба (PathName);
    # переопределяется переменной NETATLAS_AGENT_EXE (для тестов).
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add('============ ОТЧЁТ АГЕНТА NETATLAS ============')
    $lines.Add(('Время: {0}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')))
    $lines.Add(('Компьютер: {0}' -f $env:COMPUTERNAME))

    # Служба и версия.
    $svc = Get-Service -Name 'NetAtlasAgent' -ErrorAction SilentlyContinue
    if ($svc) {
        $lines.Add(('Служба NetAtlasAgent: {0}' -f $svc.Status))
    } else {
        $lines.Add('Служба NetAtlasAgent: не установлена (режим без службы или агент удалён)')
    }
    $version = 'неизвестна'
    $exeCandidates = @()
    if ($svc) {
        $pathName = (Get-CimInstance Win32_Service -Filter "Name='NetAtlasAgent'" -ErrorAction SilentlyContinue).PathName
        if ($pathName) {
            $m = [regex]::Match($pathName, '^"?([^"]+netatlas-agent\.exe)"?', 'IgnoreCase')
            if ($m.Success) { $exeCandidates += $m.Groups[1].Value.Trim() }
            $sm = [regex]::Match($pathName, '--server (\S+)')
            if ($sm.Success) { $lines.Add(('Сервер агента: {0}' -f $sm.Groups[1].Value)) }
        }
    }
    if ($env:NETATLAS_AGENT_EXE) { $exeCandidates += $env:NETATLAS_AGENT_EXE }
    foreach ($c in $exeCandidates) {
        if (Test-Path -LiteralPath $c) {
            $v = & $c --version 2>$null
            if ($LASTEXITCODE -eq 0 -and $v) { $version = ($v | Out-String).Trim() }
            break
        }
    }
    $lines.Add(('Версия агента: {0}' -f $version))

    # Соединение с сервером (порт mTLS 8443 из конфигурации службы).
    $serverLine = ($lines | Where-Object { $_ -match '^Сервер агента: ' } | Select-Object -First 1)
    if ($serverLine) {
        $u = [Uri](($serverLine -replace '^Сервер агента:\s*', ''))
        $tcp = Test-NetConnection -ComputerName $u.Host -Port $u.Port -WarningAction SilentlyContinue
        $lines.Add(('Сервер доступен ({0}:{1}): {2}' -f $u.Host, $u.Port, $(if ($tcp.TcpTestSucceeded) { 'да' } else { 'нет' })))
    }

    # Последнее успешное checkin (файл статуса пишет агент).
    $statusPath = Join-Path $agentDir 'checkin-status.json'
    if (Test-Path -LiteralPath $statusPath) {
        try {
            $st = Get-Content -LiteralPath $statusPath -Raw -Encoding UTF8 | ConvertFrom-Json
            $lines.Add(('Последнее успешное checkin: {0}' -f $st.last_checkin))
        } catch {
            $lines.Add('Последнее успешное checkin: файл статуса повреждён')
        }
    } else {
        $lines.Add('Последнее успешное checkin: неизвестно (файла статуса нет)')
    }

    # Очередь неслитых отчётов (spool): 0 = связь в норме.
    $spoolDir = Join-Path $agentDir 'spool'
    if (Test-Path -LiteralPath $spoolDir) {
        $queue = @(Get-ChildItem -LiteralPath $spoolDir -File -ErrorAction SilentlyContinue).Count
        $lines.Add(('Очередь неслитых отчётов: {0} (0 — связь с сервером в норме)' -f $queue))
    } else {
        $lines.Add('Очередь неслитых отчётов: 0 (каталог очереди не создан)')
    }

    # Последние 20 строк журнала исполнения (маскированные).
    $execLog = Join-Path $agentDir 'exec.log'
    if (Test-Path -LiteralPath $execLog) {
        $lines.Add('---- последние 20 строк exec.log (маскировано) ----')
        foreach ($l in @(Get-Content -LiteralPath $execLog -Tail 20 -Encoding UTF8 -ErrorAction SilentlyContinue)) {
            $lines.Add((Get-MaskedTextLocal -Text $l))
        }
    } else {
        $lines.Add('Журнал exec.log: пуст (задания не исполнялись)')
    }

    # Сохранение и печать.
    if (-not $OutFile) {
        $OutFile = Join-Path $env:TEMP ('netatlas-agent-report-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.txt')
    }
    [IO.File]::WriteAllLines($OutFile, $lines)
    foreach ($l in $lines) { Write-Host $l }
    Write-Host ''
    Write-Host ("ОК: отчёт сохранён: {0} — отправьте аудитору файл или текст" -f $OutFile)
}
catch {
    Write-Host ("ОШИБКА: {0}" -f (Get-MaskedTextLocal -Text $_.Exception.Message))
    exit 1
}
