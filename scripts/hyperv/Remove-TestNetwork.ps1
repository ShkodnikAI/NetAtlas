#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Удаляет объекты стенда NetAtlas на Hyper-V (NR-026).
.DESCRIPTION
    Удаляет ТОЛЬКО объекты с префиксом NetAtlas-Test- (ВМ, коммутатор,
    диски). Чужие ВМ и коммутаторы не трогаются: фильтр по префиксу
    обязателен. Без параметра -Confirm показывает план (режим -WhatIf).
.EXAMPLE
    .\Remove-TestNetwork.ps1 -Confirm
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param()

$ErrorActionPreference = 'Stop'
$prefix = 'NetAtlas-Test-'

# --- проверки окружения -------------------------------------------------

if (-not (Get-Module -ListAvailable Hyper-V)) {
    throw "Модуль Hyper-V PowerShell недоступен"
}

# --- план ---------------------------------------------------------------

$vms = Get-VM -Name "$prefix*" -ErrorAction SilentlyContinue
$switch = Get-VMSwitch -Name "$prefix*" -ErrorAction SilentlyContinue
$diskDir = Join-Path $env:PUBLIC "NetAtlas-Test-Disks"

Write-Host "План удаления (без -Confirm ничего не удалено):"
if ($vms) { Write-Host "  ВМ: $($vms.Name -join ', ')" } else { Write-Host "  ВМ с префиксом ${prefix} нет" }
if ($switch) { Write-Host "  Коммутатор: $($switch.Name)" } else { Write-Host "  Коммутатора ${prefix} нет" }
if (Test-Path $diskDir) { Write-Host "  Каталог дисков: $diskDir" } else { Write-Host "  Каталога дисков нет" }

# ConfirmImpact=High: без -Confirm будет вопрос; без ответа «да»
# ничего не удалено (план выше).
if (-not $PSCmdlet.ShouldProcess('стенд NetAtlas', 'Удалить ВМ, коммутатор и каталог дисков')) {
    Write-Warning 'Подтверждение не дано: ничего не удалено (план выше).'
    return
}

# --- удаление (только префикс NetAtlas-Test-) ---------------------------

foreach ($vm in $vms) {
    if ($PSCmdlet.ShouldProcess($vm.Name, 'Удалить ВМ стенда с дисками')) {
        if ($vm.State -ne 'Off') { Stop-VM -Name $vm.Name -Force }
        Remove-VM -Name $vm.Name -ForceDeleteDisks
    }
}
foreach ($sw in $switch) {
    if ($PSCmdlet.ShouldProcess($sw.Name, 'Удалить коммутатор стенда')) {
        Remove-VMSwitch -Name $sw.Name -Force
    }
}
if ((Test-Path $diskDir) -and $diskDir -like "*$prefix*") {
    if ($PSCmdlet.ShouldProcess($diskDir, 'Удалить каталог дисков стенда')) {
        Remove-Item -LiteralPath $diskDir -Recurse -Force
    }
}

Write-Host "Стенд NetAtlas удалён."
