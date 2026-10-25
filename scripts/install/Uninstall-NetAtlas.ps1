<#
.SYNOPSIS
    Удаление сервера NetAtlas (NR-028).
.DESCRIPTION
    Удаляет задачу планировщика NetAtlasServer и правила брандмауэра
    NetAtlas-Agent-In. Каталог установки удаляется ТОЛЬКО с -Confirm
    и только если в нём есть маркер установки .netatlas (чужие
    каталоги скрипт не трогает). Без -KeepData удаляются и данные
    (база, ключи, токен) — резервную копию сделайте заранее.
.EXAMPLE
    .\Uninstall-NetAtlas.ps1                 # снять задачу и правила
    .\Uninstall-NetAtlas.ps1 -Confirm        # + удалить каталог
    .\Uninstall-NetAtlas.ps1 -Confirm -KeepData
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [string]$Dir = 'C:\NetAtlas',
    # Не удалять data\keys\secrets\logs при удалении каталога.
    [switch]$KeepData,
    # Явное подтверждение удаления каталога.
    [switch]$Confirm
)

$ErrorActionPreference = 'Stop'
$commonPath = Join-Path $PSScriptRoot 'NetAtlas.Common.psm1'
if (Test-Path -LiteralPath $commonPath) {
    Import-Module $commonPath -Force -DisableNameChecking
}

if (-not [IO.Path]::IsPathRooted($Dir)) {
    $Dir = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Dir)
}

try {
    Write-Step 1 2 'Задача планировщика NetAtlasServer'
    if ($PSCmdlet.ShouldProcess('NetAtlasServer', 'Удалить задачу планировщика')) {
        Unregister-ScheduledTask -TaskName 'NetAtlasServer' -Confirm:$false -ErrorAction SilentlyContinue
    }
    Write-Ok 'задача удалена (или не существовала)'

    Write-Step 2 2 'Правила брандмауэра NetAtlas-Agent-In'
    if ($PSCmdlet.ShouldProcess('NetAtlas-Agent-In', 'Удалить правило брандмауэра')) {
        Remove-NetFirewallRule -DisplayName 'NetAtlas-Agent-In' -ErrorAction SilentlyContinue
    }
    Write-Ok 'правила удалены (или не существовали)'

    # Каталог: только с -Confirm и только с нашим маркером.
    $marker = Join-Path $Dir '.netatlas'
    if (Test-Path -LiteralPath $Dir) {
        if (-not (Test-Path -LiteralPath $marker)) {
            Write-Info "Каталог $Dir оставлен: нет маркера .netatlas (это не каталог установки NetAtlas)."
            return
        }
        if (-not $Confirm) {
            Write-Info "Каталог $Dir оставлен. Для полного удаления запустите с -Confirm (-KeepData сохранит данные, ключи и токен)."
            return
        }
        if ($KeepData) {
            if ($PSCmdlet.ShouldProcess($Dir, 'Удалить всё кроме data, keys, secrets, logs и маркера')) {
                foreach ($sub in @('app')) {
                    $p = Join-Path $Dir $sub
                    if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p -Recurse -Force }
                }
                Write-Ok ("удалены программы; данные, ключи, токен и логи сохранены в {0}" -f $Dir)
            }
        } else {
            if ($PSCmdlet.ShouldProcess($Dir, 'Удалить каталог установки целиком')) {
                Remove-Item -LiteralPath $Dir -Recurse -Force
                Write-Ok "каталог $Dir удалён целиком (данные не сохранялись)"
            }
        }
    } else {
        Write-Info "Каталог $Dir не найден."
    }
}
catch {
    Write-Fail $_.Exception.Message
    exit 1
}
