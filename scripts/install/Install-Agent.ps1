<#
.SYNOPSIS
    Подключение компьютера-агента (NR-029) — запуск на ЦЕЛЕВОМ ПК.
.DESCRIPTION
    Читает invite.json рядом с собой (папка приглашения от
    New-AgentInvite.ps1), проверяет срок токена и доступность порта
    регистрации, регистрирует агента (netatlas-agent enroll) и ставит
    службу (netatlas-agent install). Исполнение заданий не включается:
    оно выключено по умолчанию и включается владельцем на сервере.
    Служба запускается только после -Yes (или ответа «да»).
    После успешной регистрации invite.json и копия токена удаляются
    с диска. Скрипт самодостаточен (работает из папки приглашения).
.EXAMPLE
    .\Install-Agent.ps1 -Yes
#>
[CmdletBinding()]
param(
    # Подтверждение запуска службы (без -Yes будет вопрос).
    [switch]$Yes,
    # Режим тестов/CI: без установки службы (только регистрация).
    [switch]$NoService
)

$ErrorActionPreference = 'Stop'

# --- маскирование (скрипт самодостаточен: на целевом ПК модуля нет) ---
function Get-MaskedTextLocal {
    param([AllowEmptyString()][string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $Text }
    $out = $Text
    $out = [regex]::Replace($out, '(?i)bearer\s+[A-Za-z0-9._\-]+', 'Bearer [REDACTED]')
    $out = [regex]::Replace($out, '(?i)\b(password|passwd|pwd|token|secret|authorization)\b(\s*[=:]\s*)\S+', '$1$2[REDACTED]')
    $out = [regex]::Replace($out, '\b[A-Za-z0-9_\-]{43}\b', '[REDACTED]')
    return $out
}

function Write-StepLocal {
    param([int]$Number, [int]$Total, [string]$Message)
    Write-Host "[$Number/$Total] $Message"
}

function Write-OkLocal {
    param([string]$Message)
    Write-Host "ОК: $Message"
}

function Write-InfoLocal {
    param([string]$Message)
    Write-Host $Message
}

try {
    $invitePath = Join-Path $PSScriptRoot 'invite.json'
    if (-not (Test-Path -LiteralPath $invitePath)) {
        Write-Host 'ОШИБКА: рядом со скриптом нет invite.json (запускайте из папки приглашения, созданной New-AgentInvite.ps1)'
        exit 1
    }
    $invite = Get-Content -LiteralPath $invitePath -Raw -Encoding UTF8 | ConvertFrom-Json
    $agentExe = Join-Path $PSScriptRoot 'netatlas-agent.exe'
    $caPem = Join-Path $PSScriptRoot 'ca.pem'
    foreach ($f in @($agentExe, $caPem)) {
        if (-not (Test-Path -LiteralPath $f)) { throw "в папке приглашения нет $([IO.Path]::GetFileName($f))" }
    }

    Write-StepLocal 1 5 'Проверка срока приглашения'
    $expires = [datetime]::Parse($invite.expires_at, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeUniversal)
    if ((Get-Date) -gt $expires) {
        Write-Host ('ОШИБКА: приглашение просрочено (действовало до {0} UTC). Попросите владельца выдать новое: New-AgentInvite.ps1' -f $invite.expires_at)
        exit 1
    }
    Write-OkLocal ("приглашение действует до {0} UTC" -f $invite.expires_at)

    Write-StepLocal 2 5 'Доступность сервера (порт регистрации 8444)'
    $enrollHost = ([Uri]$invite.enroll_url).Host
    $enrollPort = ([Uri]$invite.enroll_url).Port
    $tcp = Test-NetConnection -ComputerName $enrollHost -Port $enrollPort -WarningAction SilentlyContinue
    if (-not $tcp.TcpTestSucceeded) {
        Write-Host ("ОШИБКА: сервер {0}:{1} недоступен. Чаще всего порт закрыт брандмауэром СЕРВЕРА: правило NetAtlas-Agent-In (8443/8444) должно разрешать входящие из этой подсети. Проверьте и запустите снова." -f $enrollHost, $enrollPort)
        exit 1
    }
    Write-OkLocal ("сервер {0}:{1} доступен" -f $enrollHost, $enrollPort)

    Write-StepLocal 3 5 'Регистрация агента (одноразовый токен)'
    # Регистрация — на слушателе 8444 (по токену); служба потом
    # работает через mTLS-порт 8443. Аргументы — явные строки:
    # PS 5.1 иногда теряет свойства объекта при передаче native.
    $serverArg = [string]$invite.enroll_url
    $tokenArg = [string]$invite.token
    $caArg = [string]$caPem
    $agentOut = & $agentExe enroll --server $serverArg --token $tokenArg --ca $caArg 2>&1
    if ($LASTEXITCODE -ne 0) {
        $why = Get-MaskedTextLocal -Text ($agentOut | Out-String).Trim()
        Write-Host ("ОШИБКА: регистрация отклонена ({0}). Если причина — просроченный или использованный токен, попросите владельца выдать новое приглашение." -f $why)
        exit 1
    }
    $agentId = ($agentOut | Select-Object -First 1)
    Write-OkLocal ($agentOut | Out-String).Trim()

    if ($NoService) {
        Write-StepLocal 4 5 'Служба: пропущено (-NoService, режим тестов)'
        Write-InfoLocal ('  агент зарегистрирован; каталог состояния: {0}' -f (Join-Path $env:ProgramData 'NetAtlas\agent'))
    } else {
        Write-StepLocal 4 5 'Установка службы (запуск — после подтверждения)'
        & $agentExe install --server $invite.agent_url
        if ($LASTEXITCODE -ne 0) { throw 'установка службы не удалась (нужны права администратора)' }
        # Запуск службы — только с явного подтверждения.
        $approved = $Yes
        if (-not $approved) {
            $answer = Read-Host 'Запустить службу агента сейчас? [да/нет]'
            $approved = ($answer -match '^(да|д|y|yes)$')
        }
        if ($approved) {
            Start-Service -Name 'NetAtlasAgent'
            Start-Sleep -Seconds 2
            Write-OkLocal 'служба NetAtlasAgent запущена'
        } else {
            Write-InfoLocal '  служба установлена, но не запущена: запуск позже — Start-Service NetAtlasAgent'
        }
        Write-InfoLocal '  примечание: исполнение заданий выключено по умолчанию и включается владельцем на сервере'
    }

    Write-StepLocal 5 5 'Очистка: токен не остаётся на диске'
    # invite.json содержит токен регистрации; после успешной
    # регистрации он бесполезен (одноразовый) и удаляется вместе с
    # копией. Токен нигде больше не сохранялся.
    Remove-Item -LiteralPath $invitePath -Force
    Write-OkLocal 'invite.json (с токеном) удалён из папки приглашения'

    $status = & $agentExe status 2>$null
    Write-Host ''
    Write-Host '—————— ИТОГ ——————'
    Write-Host ("ОК: агент подключён. Компьютер: {0}" -f $env:COMPUTERNAME)
    Write-Host ("  идентификация: {0}" -f ($agentId -replace 'агент зарегистрирован:\s*', ''))
    if (-not $NoService) {
        Write-Host ("  служба: {0}" -f ($(if ($status) { $status } else { 'см. netatlas-agent status' })))
    }
    Write-Host ('  каталог состояния: {0}' -f ($(if ($env:NETATLAS_AGENT_DIR) { $env:NETATLAS_AGENT_DIR } else { Join-Path $env:ProgramData 'NetAtlas\agent' })))
    Write-Host ('  журнал исполнения: {0}' -f (Join-Path ($(if ($env:NETATLAS_AGENT_DIR) { $env:NETATLAS_AGENT_DIR } else { Join-Path $env:ProgramData 'NetAtlas\agent' })) 'exec.log'))
    Write-Host '  отчёт для аудитора: powershell -NoProfile -ExecutionPolicy Bypass -File "<путь>\Get-AgentReport.ps1"'
    Write-Host '  удаление агента: powershell -NoProfile -ExecutionPolicy Bypass -File "<путь>\Uninstall-Agent.ps1" -Confirm'
}
catch {
    Write-Host ("ОШИБКА: {0}" -f (Get-MaskedTextLocal -Text $_.Exception.Message))
    Write-Host 'Что делать: исправьте причину и запустите снова (повторный запуск безопасен).'
    exit 1
}
