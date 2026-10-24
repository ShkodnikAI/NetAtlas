#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Стенд NetAtlas: виртуальная тестовая сеть на Hyper-V (NR-026).
.DESCRIPTION
    Создаёт изолированный коммутатор (Internal или Private, без
    доступа в сеть владельца) и 2-3 виртуальные машины из образа
    владельца, каждая с снимком-эталоном. Имена только
    NetAtlas-Test-*. Без параметра -Confirm ничего не делает:
    показывает план (режим -WhatIf).
.PARAMETER ImagePath
    Путь к эталонному VHDX владельца (обязательный).
.PARAMETER SwitchType
    Тип виртуального коммутатора: Internal или Private (по умолчанию
    Private — максимальная изоляция).
.PARAMETER VMCount
    Сколько ВМ создать (2-3, по умолчанию 2).
.PARAMETER VMMemoryGB
    Память ВМ в ГБ (по умолчанию 4).
.PARAMETER Confirm
    Явное подтверждение: только с ним скрипт что-то создаёт.
.EXAMPLE
    .\New-TestNetwork.ps1 -ImagePath D:\images\win11-ethalon.vhdx -Confirm
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)]
    [string]$ImagePath,
    [ValidateSet('Internal', 'Private')]
    [string]$SwitchType = 'Private',
    [ValidateRange(2, 3)]
    [int]$VMCount = 2,
    [ValidateRange(2, 16)]
    [int]$VMMemoryGB = 4,
    [switch]$Confirm
)

$ErrorActionPreference = 'Stop'
$prefix = 'NetAtlas-Test-'

# --- проверки окружения -------------------------------------------------

function Assert-Environment {
    # Редакция: только Pro/Enterprise/Education (Hyper-V не в Home).
    $caption = (Get-CimInstance Win32_OperatingSystem).Caption
    if ($caption -notmatch 'Pro|Enterprise|Education') {
        throw "Редакция Windows не поддерживает Hyper-V: $caption"
    }
    # Модуль Hyper-V установлен и включён.
    $feature = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -ErrorAction SilentlyContinue
    if ($null -eq $feature -or $feature.State -ne 'Enabled') {
        throw "Hyper-V не включён (см. docs/HYPERV.md, раздел «Включение Hyper-V»)"
    }
    if (-not (Get-Module -ListAvailable Hyper-V)) {
        throw "Модуль Hyper-V PowerShell недоступен"
    }
    # Эталонный образ существует.
    if (-not (Test-Path -LiteralPath $ImagePath)) {
        throw "Эталонный образ не найден: $ImagePath"
    }
    if ([IO.Path]::GetExtension($ImagePath) -ne '.vhdx') {
        throw "Ожидается VHDX-образ, получено: $ImagePath"
    }
    # Конфликт имён: чужие ВМ не трогаем, свои старые просим удалить.
    $existing = Get-VM -Name "$prefix*" -ErrorAction SilentlyContinue
    if ($existing) {
        throw "Уже есть ВМ с префиксом ${prefix}: удалите их скриптом Remove-TestNetwork.ps1 -Confirm"
    }
}

Assert-Environment

# --- план ---------------------------------------------------------------

$switchName = "${prefix}Switch"
$vmNames = 1..$VMCount | ForEach-Object { "${prefix}VM$_" }
$vmDiskDir = Join-Path $env:PUBLIC "NetAtlas-Test-Disks"

Write-Host "План (без -Confirm ничего не создано):"
Write-Host "  Коммутатор: $switchName ($SwitchType, изолирован от сети владельца)"
Write-Host "  ВМ: $($vmNames -join ', ') из $(Split-Path -Leaf $ImagePath) ($VMMemoryGB ГБ каждая)"
Write-Host "  Диски ВМ: $vmDiskDir"
Write-Host "  Снимок-эталон на каждой ВМ: NetAtlas-эталон"

if (-not $Confirm) {
    Write-Warning "Режим -WhatIf: выполните с -Confirm для создания стенда."
    return
}

# --- создание -----------------------------------------------------------

if ($PSCmdlet.ShouldProcess($switchName, 'Создать изолированный виртуальный коммутатор')) {
    New-VMSwitch -Name $switchName -SwitchType $SwitchType | Out-Null
}

New-Item -ItemType Directory -Path $vmDiskDir -Force | Out-Null

foreach ($name in $vmNames) {
    $disk = Join-Path $vmDiskDir "$name.vhdx"
    Copy-Item -LiteralPath $ImagePath -Destination $disk
    if ($PSCmdlet.ShouldProcess($name, 'Создать ВМ из эталонного образа')) {
        New-VM -Name $name -MemoryStartupBytes ($VMMemoryGB * 1GB) `
            -VHDPath $disk -SwitchName $switchName -Generation 2 | Out-Null
        Set-VMProcessor -VMName $name -Count 2
        Start-VM -Name $name
        # Ждём, пока ВМ загрузится (PowerShell Direct понадобится позже).
        $deadline = (Get-Date).AddMinutes(10)
        while ((Get-Date) -lt $deadline) {
            $status = (Get-VM -Name $name).Status
            if ($status -eq 'Operating normally') { break }
            Start-Sleep -Seconds 5
        }
        # Снимок-эталон: к нему возвращает Invoke-ScriptTest.ps1.
        Checkpoint-VM -Name $name -SnapshotName 'NetAtlas-эталон'
    }
}

Write-Host "Стенд готов: $($vmNames -join ', ') на коммутаторе $switchName."
Write-Host "Дальше: scripts/hyperv/Invoke-ScriptTest.ps1 (см. docs/HYPERV.md)."
