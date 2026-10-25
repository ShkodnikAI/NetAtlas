<#
.SYNOPSIS
    Удаление агента NetAtlas с этого компьютера (NR-029).
.DESCRIPTION
    Останавливает и удаляет службу NetAtlasAgent, затем удаляет
    каталог состояния агента (с -Confirm). Никаких следов токена
    регистрации не остаётся: токен никогда не сохранялся в каталоге
    агента, а invite.json удаляется при установке.
.EXAMPLE
    .\Uninstall-Agent.ps1                # служба удалена, каталог остался
    .\Uninstall-Agent.ps1 -Confirm      # + каталог состояния
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    # Удалить и каталог состояния агента.
    [switch]$Confirm
)

$ErrorActionPreference = 'Stop'
$serviceName = 'NetAtlasAgent'
$agentDir = $(if ($env:NETATLAS_AGENT_DIR) { $env:NETATLAS_AGENT_DIR } else { Join-Path $env:ProgramData 'NetAtlas\agent' })

try {
    Write-Host '[1/2] Служба NetAtlasAgent'
    $svc = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($svc) {
        if ($PSCmdlet.ShouldProcess($serviceName, 'Остановить и удалить службу')) {
            Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
            & sc.exe delete $serviceName | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "sc delete завершился с кодом $LASTEXITCODE" }
        }
        Write-Host 'ОК: служба удалена'
    } else {
        Write-Host 'ОК: служба не установлена'
    }

    Write-Host '[2/2] Каталог состояния агента'
    if (Test-Path -LiteralPath $agentDir) {
        if (-not $Confirm) {
            Write-Host ("Каталог {0} оставлен. Для полного удаления (включая ключи агента) запустите с -Confirm." -f $agentDir)
        } elseif ($PSCmdlet.ShouldProcess($agentDir, 'Удалить каталог состояния агента')) {
            Remove-Item -LiteralPath $agentDir -Recurse -Force
            Write-Host ("ОК: каталог {0} удалён" -f $agentDir)
        }
    } else {
        Write-Host 'ОК: каталог состояния не найден'
    }
    Write-Host ''
    Write-Host 'ОК: агент удалён. Следов токена регистрации нет (он одноразовый и на диск не сохранялся).'
}
catch {
    Write-Host ("ОШИБКА: {0}" -f $_.Exception.Message)
    Write-Host 'Что делать: проверьте права администратора и запустите снова.'
    exit 1
}
