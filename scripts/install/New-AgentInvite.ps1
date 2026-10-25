<#
.SYNOPSIS
    Приглашение для подключения компьютера-агента (NR-029).
.DESCRIPTION
    Запрашивает одноразовый токен регистрации (живёт час), определяет
    адрес сервера в локальной сети (подтверждается владельцем) и
    собирает папку C:\NetAtlas\invites\<имя>-<время>\: netatlas-agent.exe,
    ca.pem, Install-Agent.ps1, invite.json и zip с тем же именем.
    Папка закрывается правами (только SYSTEM и администраторы).
    Режим -Serve поднимает временный раздатчик архива в локальной
    сети на 15 минут (по умолчанию выключен): токен одноразовый и
    действует час, архив доступен только из локальной сети.
.EXAMPLE
    .\New-AgentInvite.ps1 -ComputerName PC-01 -Yes
    .\New-AgentInvite.ps1 -ComputerName PC-01 -Serve -Yes
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9._\-]{1,60}$')]
    [string]$ComputerName,

    [string]$Dir = 'C:\NetAtlas',

    # Явный адрес сервера в локальной сети (для CI и особых сетей);
    # без параметра определяется автоматически и подтверждается.
    [string]$Address,

    # Временный HTTP-раздатчик архива (по умолчанию выключен).
    [switch]$Serve,

    # Время работы раздатчика в секундах (по умолчанию 900 = 15 минут).
    [int]$ServeSeconds = 900,

    [switch]$Yes
)

$ErrorActionPreference = 'Stop'
$commonPath = Join-Path $PSScriptRoot 'NetAtlas.Common.psm1'
if (-not (Test-Path -LiteralPath $commonPath)) {
    Write-Host 'ОШИБКА: рядом со скриптом нет NetAtlas.Common.psm1 (запускайте из распакованного архива или из scripts/install)'
    exit 1
}
Import-Module $commonPath -Force -DisableNameChecking

try {
    Write-Step 1 4 'Токен регистрации (одноразовый, живёт 1 час)'
    $token = Read-OwnerToken -Dir $Dir
    $resp = Invoke-NaApi -Uri 'http://127.0.0.1:8484/api/agents/enrollment' -Method POST -Token $token -TimeoutSec 15
    $enrollToken = $resp.token
    $expiresIn = [int]$resp.expires_in_s
    $expiresAt = (Get-Date).AddSeconds($expiresIn).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    Write-Ok ("токен выдан, срок: {0} мин (до {1} UTC); в чат не вставлять" -f [int]($expiresIn / 60), $expiresAt)

    Write-Step 2 4 'Адрес сервера в локальной сети'
    if (-not $Address) {
        # Основной адаптер: активный, со шлюзом, не виртуальный.
        $ip = $null
        $cfgs = @(Get-NetIPConfiguration -ErrorAction SilentlyContinue | Where-Object { $_.IPv4DefaultGateway -and $_.IPv4Address })
        foreach ($c in $cfgs) {
            $desc = ''
            try { $desc = (Get-NetAdapter -InterfaceIndex $c.InterfaceIndex -ErrorAction Stop).InterfaceDescription } catch { }
            if (Test-VirtualAdapter -Description $desc) { continue }
            $ip = @($c.IPv4Address)[0].IPAddress
            break
        }
        if (-not $ip) { throw 'адрес сервера в локальной сети не определён; задайте вручную параметром -Address 192.168.x.x' }
        Write-Info ("  определён адрес: {0}" -f $ip)
        if (-not $Yes) {
            $answer = Read-Host 'Использовать этот адрес для подключения агентов? [да/нет]'
            if ($answer -notmatch '^(да|д|y|yes)$') {
                throw 'запустите снова с явным адресом: -Address <ip сервера в локальной сети>'
            }
        }
        $Address = $ip
    }
    $agentUrl = "https://${Address}:8443"
    $enrollUrl = "https://${Address}:8444"
    Write-Ok ("агенты будут подключаться к {0} (регистрация {1})" -f $agentUrl, $enrollUrl)

    Write-Step 3 4 'Сборка папки приглашения'
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $inviteDir = Join-Path $Dir "invites\$ComputerName-$stamp"
    $agentExe = Join-Path $Dir 'app\bin\netatlas-agent.exe'
    $caPem = Join-Path $Dir 'keys\ca.pem'
    $installAgentSrc = Join-Path $PSScriptRoot 'Install-Agent.ps1'
    $reportSrc = Join-Path $PSScriptRoot 'Get-AgentReport.ps1'
    $uninstallSrc = Join-Path $PSScriptRoot 'Uninstall-Agent.ps1'
    foreach ($f in @($agentExe, $caPem, $installAgentSrc, $reportSrc, $uninstallSrc)) {
        if (-not (Test-Path -LiteralPath $f)) { throw "не найден файл: $f (установлен ли сервер?)" }
    }
    if ($PSCmdlet.ShouldProcess($inviteDir, 'Создать папку приглашения')) {
        New-Item -ItemType Directory -Path $inviteDir -Force | Out-Null
        Copy-Item -LiteralPath $agentExe -Destination (Join-Path $inviteDir 'netatlas-agent.exe') -Force
        Copy-Item -LiteralPath $caPem -Destination (Join-Path $inviteDir 'ca.pem') -Force
        Copy-Item -LiteralPath $installAgentSrc -Destination (Join-Path $inviteDir 'Install-Agent.ps1') -Force
        Copy-Item -LiteralPath $reportSrc -Destination (Join-Path $inviteDir 'Get-AgentReport.ps1') -Force
        Copy-Item -LiteralPath $uninstallSrc -Destination (Join-Path $inviteDir 'Uninstall-Agent.ps1') -Force
        # Токен — только в invite.json внутри закрытой папки; после
        # установки Install-Agent.ps1 удаляет этот файл.
        $invite = [ordered]@{
            computer_name = $ComputerName
            agent_url     = $agentUrl
            enroll_url    = $enrollUrl
            token         = $enrollToken
            expires_at    = $expiresAt
            created_at    = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        }
        [IO.File]::WriteAllText((Join-Path $inviteDir 'invite.json'), ($invite | ConvertTo-Json))
        Protect-NetAtlasDir -Path $inviteDir
        $zipPath = "$inviteDir.zip"
        Compress-Archive -Path (Join-Path $inviteDir '*') -DestinationPath $zipPath -Force
    }
    Write-Ok ("папка: {0}" -f $inviteDir)
    Write-Ok ("архив: {0}.zip" -f $inviteDir)
    Write-NaLog -Dir $Dir -Name 'invite' -Message ("приглашение для {0}: {1} (токен не логируется)" -f $ComputerName, $inviteDir)

    Write-Step 4 4 'Как доставить на целевой компьютер'
    Write-Info ('  вариант 1 (рекомендуется): скопируйте папку {0}' -f "$ComputerName-$stamp")
    Write-Info '    на целевой компьютер по сети (\\\\server\\invites\\...) или на флешке.'
    Write-Info '  вариант 2: скопируйте одноимённый zip и распакуйте на целевом компьютере.'
    Write-Info '  Затем на целевом компьютере (PowerShell, администратор):'
    Write-Info ('    powershell -NoProfile -ExecutionPolicy Bypass -File "<путь>\Install-Agent.ps1" -Yes')
    Write-Info '  Токен одноразовый: после первой установки он больше не действует.'

    if ($Serve) {
        if ($PSCmdlet.ShouldProcess("${Address}:8765", 'Поднять временный раздатчик архива')) {
            Write-Warning 'Раздатчик включён (-Serve): архив будет доступен из локальной сети по http. Токен одноразовый и действует 1 час; раздаётся только один файл и на ограниченное время.'
            $serveDir = $inviteDir
            $zipName = "$ComputerName-$stamp.zip"
            $served = $false
            $listener = [System.Net.HttpListener]::new()
            $listener.Prefixes.Add("http://${Address}:8765/")
            $listener.Start()
            Write-Ok ("раздатчик: http://{0}:8765/{1} (закроется через {2} с или после первой отдачи)" -f $Address, $zipName, $ServeSeconds)
            Write-Info ('  Команда для целевого ПК:')
            Write-Info ("    `"`$d=`$env:TEMP\na-invite; Invoke-WebRequest 'http://{0}:8765/{1}' -OutFile `$d.zip; Expand-Archive `$d.zip `$d -Force; powershell -NoProfile -ExecutionPolicy Bypass -File `"`$d\Install-Agent.ps1`" -Yes`"" -f $Address, $zipName)
            $deadline = (Get-Date).AddSeconds($ServeSeconds)
            while ((Get-Date) -lt $deadline -and -not $served) {
                $ctx = $listener.BeginGetContext($null, $null)
                while (-not $ctx.IsCompleted) {
                    if ((Get-Date) -gt $deadline) { break }
                    Start-Sleep -Milliseconds 200
                }
                if ($ctx.IsCompleted) {
                    $result = $listener.EndGetContext($ctx)
                    try {
                        if ($result.Request.Url.AbsolutePath -eq "/$zipName") {
                            $bytes = [IO.File]::ReadAllBytes("$serveDir.zip")
                            $result.Response.ContentType = 'application/zip'
                            $result.Response.ContentLength64 = $bytes.Length
                            $result.Response.OutputStream.Write($bytes, 0, $bytes.Length)
                            # Закрыть ответ ДО остановки слушателя: иначе
                            # клиент получает обрыв соединения.
                            $result.Response.OutputStream.Flush()
                            $result.Response.Close()
                            $served = $true
                            Write-Ok 'архив отдан; раздатчик закрывается (раздаётся только один архив)'
                        } else {
                            $result.Response.StatusCode = 404
                            $result.Response.Close()
                        }
                    } catch { }
                }
            }
            $listener.Stop()
            $listener.Close()
            if (-not $served) { Write-Info 'Раздатчик закрыт по времени: архив никому не отдан.' }
        }
    }
}
catch {
    Write-Fail $_.Exception.Message
    Write-NaLog -Dir $Dir -Name 'invite' -Message ("ОШИБКА: {0}" -f $_.Exception.Message)
    exit 1
}
