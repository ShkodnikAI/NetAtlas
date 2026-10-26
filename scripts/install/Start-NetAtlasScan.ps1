<#
.SYNOPSIS
    Запуск сканирования сети и печать сводки (NR-028).
.DESCRIPTION
    Читает токен владельца и подсети из файлов установки, запускает
    сканирование через POST /api/scan (ping, имена, подтверждение),
    опрашивает состояние до конца и печатает сводку: устройства по
    классам, хосты без MAC, ошибки этапов, длительность. Ничего не
    пишет за пределы базы NetAtlas (кроме журнала в logs\ без секретов).
.EXAMPLE
    .\Start-NetAtlasScan.ps1
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$Dir = 'C:\NetAtlas',
    # Цели SNMP-опроса портов (только внутри подсетей сервера).
    [string[]]$SnmpTargets,
    # Максимальное ожидание сканирования.
    [int]$TimeoutSec = 2100
)

$ErrorActionPreference = 'Stop'
$commonPath = Join-Path $PSScriptRoot 'NetAtlas.Common.psm1'
if (-not (Test-Path -LiteralPath $commonPath)) {
    Write-Host 'ОШИБКА: рядом со скриптом нет NetAtlas.Common.psm1 (запускайте из распакованного архива или из scripts/install)'
    exit 1
}
Import-Module $commonPath -Force -DisableNameChecking

$sw = [System.Diagnostics.Stopwatch]::StartNew()
try {
    $token = Read-OwnerToken -Dir $Dir
    $subnetsFile = Join-Path $Dir 'data\subnets.txt'
    if (-not (Test-Path -LiteralPath $subnetsFile)) {
        throw "нет файла подсетей: $subnetsFile (запустите Install-NetAtlas.ps1)"
    }
    $subnets = @(Get-Content -LiteralPath $subnetsFile | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    if ($subnets.Count -eq 0) { throw 'список подсетей пуст' }

    if (-not $PSCmdlet.ShouldProcess('http://127.0.0.1:8484', "Запустить сканирование подсетей $($subnets -join ', ')")) {
        Write-Warning 'Режим -WhatIf: сканирование не запускалось.'
        return
    }

    Write-Step 1 3 'Запуск сканирования (POST /api/scan)'
    $body = @{
        subnets      = $subnets
        ping         = $true
        names        = $true
        confirm      = $true
        snmp_targets = @($SnmpTargets | Where-Object { $_ })
    }
    $resp = Invoke-NaApi -Uri 'http://127.0.0.1:8484/api/scan' -Method POST -Token $token `
        -JsonBody ($body | ConvertTo-Json -Depth 4)
    $scanId = $resp.id
    Write-Ok ("сканирование запущено, идентификатор {0}" -f $scanId)
    Write-NaLog -Dir $Dir -Name 'scan' -Message ("запущено сканирование {0}: {1}" -f $scanId, ($subnets -join ','))

    Write-Step 2 3 'Ожидание завершения'
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    $state = $null
    while ($true) {
        Start-Sleep -Seconds 5
        $state = Invoke-NaApi -Uri "http://127.0.0.1:8484/api/scan/$scanId" -Token $token
        if ($state.status -ne 'running') { break }
        if ((Get-Date) -gt $deadline) {
            Write-Fail "сканирование не завершилось за $TimeoutSec секунд; состояние сохранено на сервере"
            throw 'таймаут ожидания сканирования'
        }
    }
    Write-Ok ("состояние: {0}" -f $state.status)

    Write-Step 3 3 'Сводка'
    if ($state.status -eq 'failed') {
        Write-Fail ("сканирование не удалось: {0}" -f $state.error)
        throw 'сканирование завершилось ошибкой (подробности выше и в logs\scan.log)'
    }
    $c = $state.counts
    Write-Host ''
    Write-Host '—————— СВОДКА СКАНИРОВАНИЯ ——————'
    Write-Host ("Подсети: {0}" -f ($state.subnets -join ', '))
    Write-Host ("Устройств: {0}, хостов: {1}, связей: {2}" -f $c.devices, $c.hosts, $c.links)
    if ($c.leases -gt 0 -or $c.leases_skipped -gt 0) {
        Write-Host ("DHCP-аренд: {0} (пропущено {1})" -f $c.leases, $c.leases_skipped)
    }
    # Хосты без MAC: из списка устройств после скана.
    try {
        $devs = Invoke-NaApi -Uri 'http://127.0.0.1:8484/api/devices' -Token $token
        $noMac = @($devs | Where-Object { $_.class -eq 'host' -and -not $_.mac })
        Write-Host ("Хостов без MAC: {0}" -f $noMac.Count)
    } catch {
        Write-Info '  (список устройств недоступен: хосты без MAC не посчитаны)'
    }
    if ($state.stages) {
        Write-Host ("Этапы: {0}" -f ($state.stages -join ' → '))
    }
    $dur = [int]$sw.Elapsed.TotalSeconds
    Write-Host ("Длительность: {0} м {1:00} с" -f ([int]($dur / 60)), ($dur % 60))
    Write-Host 'Карта: http://127.0.0.1:8484'
    Write-NaLog -Dir $Dir -Name 'scan' -Message ("сканирование {0}: devices={1} hosts={2} links={3}, {4} с" -f $scanId, $c.devices, $c.hosts, $c.links, $dur)
}
catch {
    Write-Fail $_.Exception.Message
    Write-NaLog -Dir $Dir -Name 'scan' -Message ("ОШИБКА: {0}" -f $_.Exception.Message)
    exit 1
}
