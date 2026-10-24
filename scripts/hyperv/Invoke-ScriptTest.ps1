#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Тест скрипта на ВМ стенда перед подписью (NR-026).
.DESCRIPTION
    Восстанавливает снимок-эталон, копирует скрипт на ВМ через
    PowerShell Direct, запускает с таймаутом, собирает код возврата,
    вывод и метрики до/после (задержка до хоста, свободное место,
    статусы служб из списка), откатывает снимок и записывает JSON
    результат. Результат отправляется на сервер владельцем
    (POST /api/test-runs) — см. docs/HYPERV.md.
.EXAMPLE
    .\Invoke-ScriptTest.ps1 -ScriptPath .\script.ps1 -VMName NetAtlas-Test-VM1 -Credential (Get-Credential) -Confirm
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)]
    [string]$ScriptPath,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^NetAtlas-Test-')]
    [string]$VMName,
    [Parameter(Mandatory = $true)]
    [pscredential]$Credential,
    [ValidateRange(10, 1800)]
    [int]$TimeoutSec = 300,
    [string]$ServerUrl = 'http://127.0.0.1:8484',
    [string]$Token,
    [string[]]$ServiceNames = @('Spooler', 'Dnscache'),
    [switch]$Confirm
)

$ErrorActionPreference = 'Stop'
$snapshotName = 'NetAtlas-эталон'
$remoteScriptPath = 'C:\NetAtlas-Test\job.ps1'

# --- проверки -----------------------------------------------------------

if (-not (Test-Path -LiteralPath $ScriptPath)) {
    throw "Скрипт не найден: $ScriptPath"
}
$scriptContent = Get-Content -LiteralPath $ScriptPath -Raw
$scriptSha = (Get-FileHash -LiteralPath $ScriptPath -Algorithm SHA256).Hash.ToLowerInvariant()
$vm = Get-VM -Name $VMName -ErrorAction SilentlyContinue
if ($null -eq $vm) {
    throw "ВМ стенда не найдена (префикс NetAtlas-Test-): $VMName"
}
$snapshot = Get-VMSnapshot -VMName $VMName | Where-Object { $_.Name -eq $snapshotName }
if ($null -eq $snapshot) {
    throw "Снимок-эталон не найден: сначала New-TestNetwork.ps1 -Confirm"
}
if (-not $Confirm) {
    Write-Warning "Режим -WhatIf: план — восстановить '$snapshotName' на $VMName, скопировать скрипт ($($scriptContent.Length) байт), запустить с таймаутом ${TimeoutSec}с, собрать метрики, откатить снимок."
    return
}

# --- метрики внутри ВМ --------------------------------------------------

function Get-VMState {
    param([pscredential]$Cred)
    Invoke-Command -VMName $VMName -Credential $Cred -ScriptBlock {
        $services = Get-Service -Name $using:ServiceNames -ErrorAction SilentlyContinue |
            Select-Object Name, Status
        [pscustomobject]@{
            FreeSpaceGB = [math]::Round((Get-PSDrive C).Free / 1GB, 2)
            PingMs = $null   # заполняется хостом ниже (ICMP на хосте)
            Services = $services
            UptimeSec = [math]::Round([Environment]::TickCount64 / 1000, 0)
        }
    }
}

function Test-HostPing {
    # Задержка от ВМ до хоста: ICMP с хоста на IP ВМ.
    $ip = (Get-VMNetworkAdapter -VMName $VMName).IPAddresses |
        Where-Object { $_ -match '^\d+\.\d+\.' } | Select-Object -First 1
    if (-not $ip) { return $null }
    $reply = Test-Connection -ComputerName $ip -Count 3 -ErrorAction SilentlyContinue
    if ($reply) {
        return [math]::Round(($reply | Measure-Object -Property ResponseTime -Average).Average, 1)
    }
    return $null
}

# --- прогон -------------------------------------------------------------

$result = [ordered]@{
    script_sha256 = $scriptSha
    stage = 'vm'
    result = 'fail'
    metrics = [ordered]@{}
    log = @()
    ran_at = (Get-Date).ToUniversalTime().ToString('o')
}

try {
    # 1. Восстановить снимок-эталон: чистое состояние перед тестом.
    $result.log += "Восстановление снимка '$snapshotName'"
    Restore-VMSnapshot -VMName $VMName -Name $snapshotName -Confirm:$false
    Wait-VM -Name $VMName -For Heartbeat -TimeoutSec 180

    # 2. Копировать скрипт на ВМ (PowerShell Direct).
    $result.log += "Копирование скрипта ($($scriptContent.Length) байт) в $remoteScriptPath"
    Invoke-Command -VMName $VMName -Credential $Credential -ScriptBlock {
        New-Item -ItemType Directory -Path 'C:\NetAtlas-Test' -Force | Out-Null
    }
    $remote = Invoke-Command -VMName $VMName -Credential $Credential -ScriptBlock {
        param($path, $content) Set-Content -Path $path -Value $content -Encoding UTF8
    } -ArgumentList $remoteScriptPath, $scriptContent

    # 3. Метрики «до».
    $before = Get-VMState -Cred $Credential
    $before.PingMs = Test-HostPing
    $result.metrics.before = $before
    $result.log += "Метрики до: место $($before.FreeSpaceGB) ГБ, службы $($before.Services.Count) шт"

    # 4. Запуск с таймаутом.
    $result.log += "Запуск с таймаутом ${TimeoutSec}с"
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $invocation = Invoke-Command -VMName $VMName -Credential $Credential -ScriptBlock {
        param($path)
        $out = & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $path 2>&1
        [pscustomobject]@{ Code = $LASTEXITCODE; Output = ($out | Out-String) }
    } -ArgumentList $remoteScriptPath -ErrorAction Stop
    $sw.Stop()

    $result.log += "Выполнено за $([math]::Round($sw.Elapsed.TotalSeconds, 1)) с, код $($invocation.Code), вывод $($invocation.Output.Length) симв."
    if ($sw.Elapsed.TotalSeconds -gt $TimeoutSec) {
        $result.log += "Превышен таймаут ${TimeoutSec}с"
    } elseif ($invocation.Code -eq 0) {
        $result.result = 'pass'
    }
    $result.log += "Вывод (первые 4000 символов):"
    $result.log += $invocation.Output.Substring(0, [Math]::Min(4000, $invocation.Output.Length))

    # 5. Метрики «после».
    $after = Get-VMState -Cred $Credential
    $after.PingMs = Test-HostPing
    $result.metrics.after = $after
}
catch {
    $result.log += "ОШИБКА: $($_.Exception.Message)"
    $result.result = 'fail'
}
finally {
    # 6. Откат снимка: ВМ всегда возвращается в эталонное состояние.
    if ($PSCmdlet.ShouldProcess($VMName, "Откатить снимок '$snapshotName'")) {
        try {
            Stop-VM -Name $VMName -Force -ErrorAction SilentlyContinue
            Restore-VMSnapshot -VMName $VMName -Name $snapshotName -Confirm:$false
            $result.log += "Снимок откатан: ВМ в эталонном состоянии"
        }
        catch {
            $result.log += "ОТКАТ НЕ УДАЛСЯ: $($_.Exception.Message)"
        }
    }
}

# 7. JSON результат: файл рядом со скриптом + на сервер при наличии токена.
$outFile = Join-Path (Split-Path -Parent $ScriptPath) ("test-result-" + (Get-Date -Format 'yyyyMMdd-HHmmss') + ".json")
$result | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $outFile -Encoding UTF8
Write-Host "Результат: $outFile"

if ($Token) {
    $headers = @{ Authorization = "Bearer $Token" }
    $body = @{
        script_sha256 = $scriptSha
        stage = 'vm'
        result = $result.result
        metrics = @{}
        log = ($result.log -join "`n")
    }
    if ($result.metrics.before -and $result.metrics.after) {
        $body.metrics = @{
            before = @{ uptime_sec = $result.metrics.before.UptimeSec; free_space_gb = $result.metrics.before.FreeSpaceGB }
            after = @{ uptime_sec = $result.metrics.after.UptimeSec; free_space_gb = $result.metrics.after.FreeSpaceGB }
        }
    }
    try {
        Invoke-RestMethod -Method Post -Uri "$ServerUrl/api/test-runs" -Headers $headers -Body ($body | ConvertTo-Json -Depth 5) -ContentType 'application/json' | Out-Null
        Write-Host "Результат отправлен на сервер."
    }
    catch {
        Write-Warning "Не удалось отправить результат на сервер: $($_.Exception.Message)"
    }
}
