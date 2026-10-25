<#
.SYNOPSIS
    Установка сервера NetAtlas одной вставкой (NR-028).
.DESCRIPTION
    Девять шагов с печатью «[N/9] ...»: проверка окружения, получение
    релиза, структура каталогов с закрытыми правами, ключи PKI, токен
    владельца (в буфер обмена, не в консоль), подсети, run-server.ps1,
    задача планировщика и брандмауэр, ожидание API. Повторный запуск
    безопасен: существующие ключи и токен не заменяются.
    Без прав администратора не работает (кроме режимов -NoService и
    -WhatIf: проверки окружения всё равно требуют системы Windows).
.PARAMETER Version
    Версия релиза (v0.1.0) или latest (по умолчанию).
.PARAMETER Dir
    Каталог установки (по умолчанию C:\NetAtlas).
.PARAMETER Subnets
    Подсети через запятую; без параметра определяются автоматически
    с подтверждением.
.PARAMETER ZipPath
    Ручная установка из скачанного архива (если скачивание из
    GitHub недоступно).
.PARAMETER LocalBinDir
    Каталог с собранными .exe (для CI; пропускает скачивание).
.PARAMETER NoService
    Не создавать задачу планировщика и правила брандмауэра (для
    тестов; сервер потом запускается run-server.ps1 вручную).
.PARAMETER RotateToken
    Заменить токен владельца новым (старый перестаёт работать).
.PARAMETER Yes
    Не задавать вопросов (подтверждение подсетей пропускается).
.EXAMPLE
    .\Install-NetAtlas.ps1 -Yes
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$Version = 'latest',
    [string]$Dir = 'C:\NetAtlas',
    [string]$Subnets,
    [string]$ZipPath,
    [string]$LocalBinDir,
    [switch]$NoService,
    [switch]$RotateToken,
    [switch]$Yes
)

$ErrorActionPreference = 'Stop'
$total = 9

# Модуль помощников лежит рядом со скриптом (в архиве и в репозитории).
$commonPath = Join-Path $PSScriptRoot 'NetAtlas.Common.psm1'
if (-not (Test-Path -LiteralPath $commonPath)) {
    Write-Host 'ОШИБКА: рядом со скриптом нет NetAtlas.Common.psm1 (запускайте из распакованного архива или из scripts/install)'
    exit 1
}
Import-Module $commonPath -Force -DisableNameChecking

$repo = 'ShkodnikAI/NetAtlas'
$serverPort = 8484
$sw = [System.Diagnostics.Stopwatch]::StartNew()

function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    return (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

try {
    # --- шаг 1: окружение ---------------------------------------------------
    Write-Step 1 $total 'Проверка окружения'
    if ($PSVersionTable.PSVersion.Major -lt 5 -or ($PSVersionTable.PSVersion.Major -eq 5 -and $PSVersionTable.PSVersion.Minor -lt 1)) {
        throw 'нужен Windows PowerShell 5.1 или новее'
    }
    if (-not (Assert-Admin)) {
        if (-not $NoService) {
            throw 'нужны права администратора (окно PowerShell запущено не от администратора)'
        }
        Write-Info '  примечание: без прав администратора (режим -NoService)'
    }
    $os = Get-CimInstance Win32_OperatingSystem
    Write-Info ("  система: {0} (сборка {1})" -f $os.Caption, $os.BuildNumber)
    if ($os.Caption -notmatch 'Windows 10|Windows 11|Windows Server') {
        throw "неподдерживаемая система: $($os.Caption)"
    }
    # Hyper-V — только справка (редакция владельца неизвестна, не блокирует).
    try {
        $hv = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -ErrorAction Stop
        if ($hv -and $hv.State -eq 'Enabled') {
            Write-Info '  Hyper-V: включён (скрипты установки его не требуют)'
        } else {
            Write-Info '  Hyper-V: не включён (справочно; для установки не нужен, для стенда см. docs/HYPERV.md)'
        }
    } catch {
        Write-Info '  Hyper-V: состояние неизвестно (справочно; на установку не влияет)'
    }
    Write-NaLog -Dir $Dir -Name 'install' -Message 'шаг 1/9: окружение проверено'
    Write-Ok 'окружение проверено'

    # Относительный -Dir -> абсолютный (все пути дальше абсолютные).
    if (-not [IO.Path]::IsPathRooted($Dir)) {
        $Dir = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Dir)
    }

    # Повторная установка: работающий сервер держит .exe — обновить
    # бинарники нельзя. Останавливаем и процесс, и задачу; задача
    # запустит сервер снова (или владелец run-server.ps1 в -NoService).
    Get-Process netatlas-server -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Stop-ScheduledTask -TaskName 'NetAtlasServer' -ErrorAction SilentlyContinue

    # --- шаг 2: архив релиза ------------------------------------------------
    Write-Step 2 $total 'Получение архива релиза и проверка хэша'
    $appDir = Join-Path $Dir 'app'
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ("netatlas-install-" + [IO.Path]::GetRandomFileName())
    New-Item -ItemType Directory -Path $tmp -Force | Out-Null
    if ($LocalBinDir) {
        Write-Info "  режим CI: бинарники из $LocalBinDir (скачивание пропущено)"
        if (-not (Test-Path -LiteralPath (Join-Path $LocalBinDir 'netatlas-server.exe'))) {
            throw "в -LocalBinDir нет netatlas-server.exe: $LocalBinDir"
        }
    } else {
        $headers = @{}
        if ($env:NETATLAS_GH_TOKEN) {
            $headers['Authorization'] = "token $($env:NETATLAS_GH_TOKEN)"
        }
        $zipUrl = $null
        $sumsUrl = $null
        if ($ZipPath) {
            Write-Info "  ручная установка из $ZipPath"
        } else {
            if ($Version -eq 'latest') {
                try {
                    $rel = Invoke-RestMethod -Uri "https://api.github.com/repos/$repo/releases/latest" -Headers $headers -TimeoutSec 30
                    $Version = $rel.tag_name
                } catch {
                    throw "не удалось узнать последнюю версию релиза (репозиторий закрыт?): запустите с -ZipPath <путь к скачанному архиву> или задайте переменную NETATLAS_GH_TOKEN"
                }
            }
            $base = "https://github.com/$repo/releases/download/$Version"
            $zipUrl = "$base/netatlas-$Version-windows-amd64.zip"
            $sumsUrl = "$base/SHA256SUMS.txt"
            Write-Info "  скачивание: $zipUrl"
        }
        if ($ZipPath) {
            Copy-Item -LiteralPath $ZipPath -Destination (Join-Path $tmp 'release.zip') -Force
            $sumsPath = Join-Path (Split-Path -Parent $ZipPath) 'SHA256SUMS.txt'
            if (Test-Path -LiteralPath $sumsPath) {
                Copy-Item -LiteralPath $sumsPath -Destination (Join-Path $tmp 'SHA256SUMS.txt') -Force
            }
        } else {
            try {
                Invoke-WebRequest -Uri $zipUrl -OutFile (Join-Path $tmp 'release.zip') -Headers $headers -TimeoutSec 300
                Invoke-WebRequest -Uri $sumsUrl -OutFile (Join-Path $tmp 'SHA256SUMS.txt') -Headers $headers -TimeoutSec 60
            } catch {
                $hint = 'запустите с -ZipPath <путь к скачанному архиву>'
                if (-not $env:NETATLAS_GH_TOKEN) { $hint += ' или задайте переменную NETATLAS_GH_TOKEN (репозиторий закрыт)' }
                throw "скачивание не удалось: $($_.Exception.Message); $hint"
            }
        }
        # Хэш архива по SHA256SUMS.txt (если суммы есть).
        $sumsFile = Join-Path $tmp 'SHA256SUMS.txt'
        $zipFile = Join-Path $tmp 'release.zip'
        if (Test-Path -LiteralPath $sumsFile) {
            $zipName = 'release.zip'
            $expected = $null
            foreach ($line in (Get-Content -LiteralPath $sumsFile)) {
                if ($line -match '([0-9a-fA-F]{64})\s\s?(.+)$') {
                    if ((Split-Path -Leaf $Matches[2]) -like '*.zip') { $expected = $Matches[1].ToLowerInvariant() }
                }
            }
            if ($expected) {
                $actual = (Get-FileHash -LiteralPath $zipFile -Algorithm SHA256).Hash.ToLowerInvariant()
                if ($actual -ne $expected) {
                    throw 'хэш архива не совпал с SHA256SUMS.txt: файл повреждён или подменён, установка прервана'
                }
                Write-Info '  хэш архива совпал с SHA256SUMS.txt'
            } else {
                Write-Info '  примечание: в SHA256SUMS.txt нет архива — хэш не сверён'
            }
        } else {
            Write-Info '  примечание: SHA256SUMS.txt не скачался — хэш не сверён'
        }
        if ($PSCmdlet.ShouldProcess($appDir, 'Распаковать архив релиза')) {
            New-Item -ItemType Directory -Path $appDir -Force | Out-Null
            Expand-Archive -LiteralPath $zipFile -DestinationPath $appDir -Force
        }
        Write-Ok "архив распакован в $appDir"
    }
    if ($LocalBinDir) {
        if ($PSCmdlet.ShouldProcess($appDir, 'Скопировать локальные бинарники')) {
            New-Item -ItemType Directory -Path (Join-Path $appDir 'bin') -Force | Out-Null
            Copy-Item -Path (Join-Path $LocalBinDir '*.exe') -Destination (Join-Path $appDir 'bin') -Force
            foreach ($extra in @('VERSION.txt', 'LICENSE')) {
                $src = Join-Path $LocalBinDir $extra
                if (Test-Path -LiteralPath $src) { Copy-Item -LiteralPath $src -Destination $appDir -Force }
            }
        }
        Write-Ok "бинарники скопированы в $appDir\bin"
    }
    Write-NaLog -Dir $Dir -Name 'install' -Message 'шаг 2/9: архив получен и проверен'

    # --- шаг 3: структура каталогов и права ---------------------------------
    Write-Step 3 $total 'Создание каталогов и закрытие прав'
    foreach ($sub in @('app', 'keys', 'data', 'logs', 'secrets')) {
        New-Item -ItemType Directory -Path (Join-Path $Dir $sub) -Force | Out-Null
    }
    $marker = Join-Path $Dir '.netatlas'
    if (-not (Test-Path -LiteralPath $marker)) {
        Set-Content -LiteralPath $marker -Value "NetAtlas installation marker (NR-028)"
    }
    if ($PSCmdlet.ShouldProcess($Dir, 'Закрыть права на keys и secrets (только SYSTEM и администраторы)')) {
        Protect-NetAtlasDir -Path (Join-Path $Dir 'keys')
        Protect-NetAtlasDir -Path (Join-Path $Dir 'secrets')
    }
    Write-NaLog -Dir $Dir -Name 'install' -Message 'шаг 3/9: каталоги созданы, права закрыты'
    Write-Ok 'каталоги созданы; keys и secrets закрыты (SYSTEM и администраторы)'

    # --- шаг 4: ключи PKI ----------------------------------------------------
    Write-Step 4 $total 'Ключи PKI (netatlas-pki init)'
    $pkiExe = Join-Path $appDir 'bin\netatlas-pki.exe'
    $keysDir = Join-Path $Dir 'keys'
    if (Test-Path -LiteralPath (Join-Path $keysDir 'ca.pem')) {
        Write-Info '  ключи уже существуют: пропускаю (повтор не перезаписывает ключи)'
    } else {
        if (-not (Test-Path -LiteralPath $pkiExe)) { throw "нет $pkiExe" }
        $env:NETATLAS_KEYDIR = $keysDir
        & $pkiExe init
        if ($LASTEXITCODE -ne 0) { throw 'netatlas-pki init завершился с ошибкой' }
        Remove-Item Env:NETATLAS_KEYDIR -ErrorAction SilentlyContinue
        Write-Ok ('ключи созданы в {0}' -f $keysDir)
    }
    Write-NaLog -Dir $Dir -Name 'install' -Message 'шаг 4/9: ключи PKI готовы'

    # --- шаг 5: токен владельца ----------------------------------------------
    Write-Step 5 $total 'Токен владельца'
    $created = Save-OwnerToken -Dir $Dir -Rotate:$RotateToken
    if ($created) {
        if ($RotateToken) { Write-Info '  токен заменён (-RotateToken)' }
        else { Write-Info '  токен создан' }
    } else {
        Write-Info '  токен уже существует: не меняю (заменить: -RotateToken)'
    }
    # Токен только в буфер обмена; в консоль не печатается.
    $clipboardNote = 'токен в файле secrets\owner-token.txt'
    try {
        $tokForClipboard = Read-OwnerToken -Dir $Dir
        Set-Clipboard -Value $tokForClipboard -ErrorAction Stop
        $clipboardNote = 'токен в буфере обмена — В ЧАТ НЕ ВСТАВЛЯТЬ (копия в secrets\owner-token.txt)'
    } catch {
        Write-Info '  буфер обмена недоступен: токен только в файле secrets\owner-token.txt'
    }
    Write-Info ("  {0}" -f $clipboardNote)
    Write-NaLog -Dir $Dir -Name 'install' -Message 'шаг 5/9: токен владельца готов (значение не логируется)'

    # --- шаг 6: подсети ------------------------------------------------------
    Write-Step 6 $total 'Подсети для сканирования'
    $subnetList = @()
    if ($Subnets) {
        $subnetList = @($Subnets.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        Write-Info ("  заданы параметром: {0}" -f ($subnetList -join ', '))
    } else {
        $subnetList = @(Get-LanSubnets)
        if ($subnetList.Count -eq 0) {
            throw 'подсети не найдены (нет адаптера со шлюзом?): задайте вручную параметром -Subnets 192.168.1.0/24'
        }
        Write-Info ("  найдено: {0}" -f ($subnetList -join ', '))
        if (-not $Yes) {
            $answer = Read-Host 'Сканировать эти подсети? [да/нет]'
            if ($answer -notmatch '^(да|д|y|yes)$') {
                throw 'уточните подсети и запустите снова с -Subnets <список через запятую>'
            }
        }
    }
    Set-Content -LiteralPath (Join-Path $Dir 'data\subnets.txt') -Value ($subnetList -join [Environment]::NewLine) -Encoding ASCII
    Write-NaLog -Dir $Dir -Name 'install' -Message ("шаг 6/9: подсети {0}" -f ($subnetList -join ','))
    Write-Ok ('подсети сохранены в data\subnets.txt: {0}' -f ($subnetList -join ', '))

    # --- шаг 7: run-server.ps1 ------------------------------------------------
    Write-Step 7 $total 'Запускающий файл run-server.ps1'
    $runScript = Join-Path $appDir 'run-server.ps1'
    $subnetsJoined = ($subnetList -join ',')
    $runContent = @"
# run-server.ps1 — запускает сервер NetAtlas (создан Install-NetAtlas.ps1).
# Токен и ключи читаются из файлов в момент старта; в самом файле и
# в аргументах их нет.
`$ErrorActionPreference = 'Stop'
`$dir = '$Dir'
`$token = (Get-Content -LiteralPath (Join-Path `$dir 'secrets\owner-token.txt') -TotalCount 1).Trim()
`$env:NETATLAS_TOKEN = `$token
`$env:NETATLAS_KEYDIR = Join-Path `$dir 'keys'
`$server = Join-Path `$dir 'app\bin\netatlas-server.exe'
`$logStamp = Get-Date -Format 'yyyyMMdd'
`$outLog = Join-Path `$dir ('logs\server-out-' + `$logStamp + '.log')
`$errLog = Join-Path `$dir ('logs\server-err-' + `$logStamp + '.log')
Start-Process -FilePath `$server -ArgumentList @(
    '--db', (Join-Path `$dir 'data\netatlas.db'),
    '--subnets', '$subnetsJoined',
    '--agent-listen', '0.0.0.0:8443',
    '--agent-enroll-listen', '0.0.0.0:8444',
    '--allow-remote'
) -WindowStyle Hidden -RedirectStandardOutput `$outLog -RedirectStandardError `$errLog
Write-Host "сервер запущен; журнал: logs\server-err-`$logStamp.log; владелец: http://127.0.0.1:8484"
"@
    if ($PSCmdlet.ShouldProcess($runScript, 'Создать запускающий файл')) {
        Set-Content -LiteralPath $runScript -Value $runContent -Encoding UTF8
    }
    Write-NaLog -Dir $Dir -Name 'install' -Message 'шаг 7/9: run-server.ps1 создан (слушатель владельца 127.0.0.1:8484, агенты 8443/8444)'
    Write-Ok "run-server.ps1 создан (владелец: http://127.0.0.1:8484, только локально)"

    # --- шаг 8: планировщик и брандмауэр --------------------------------------
    if ($NoService) {
        Write-Step 8 $total 'Задача планировщика и брандмауэр: пропущено (-NoService)'
        Write-Info '  сервер запускается вручную: app\run-server.ps1'
    } else {
        Write-Step 8 $total 'Задача планировщика NetAtlasServer и правила брандмауэра'
        $action = New-ScheduledTaskAction -Execute 'powershell.exe' `
            -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$runScript`""
        $trigger = New-ScheduledTaskTrigger -AtStartup
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
            -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero)
        $principal = New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -LogonType ServiceAccount -RunLevel Highest
        if ($PSCmdlet.ShouldProcess('NetAtlasServer', 'Зарегистрировать задачу планировщика (запуск при старте, SYSTEM)')) {
            Unregister-ScheduledTask -TaskName 'NetAtlasServer' -Confirm:$false -ErrorAction SilentlyContinue
            Register-ScheduledTask -TaskName 'NetAtlasServer' -Action $action -Trigger $trigger `
                -Settings $settings -Principal $principal -Force | Out-Null
            Start-ScheduledTask -TaskName 'NetAtlasServer'
        }
        Write-Ok 'задача NetAtlasServer зарегистрирована и запущена (SYSTEM, автозапуск, перезапуск при сбое)'
        $remote = $subnetList
        if ($PSCmdlet.ShouldProcess('Брандмауэр', "Разрешить входящие 8443/8444 только из $remote")) {
            Remove-NetFirewallRule -DisplayName 'NetAtlas-Agent-In' -ErrorAction SilentlyContinue
            New-NetFirewallRule -DisplayName 'NetAtlas-Agent-In' -Direction Inbound -Action Allow `
                -Protocol TCP -LocalPort 8443,8444 -RemoteAddress $remote | Out-Null
        }
        Write-Ok "брандмауэр: входящие 8443/8444 только из подсетей ($($remote -join ', ')); порт 8484 наружу не открыт"
        Write-NaLog -Dir $Dir -Name 'install' -Message 'шаг 8/9: задача и правила брандмауэра созданы'
    }

    # --- шаг 9: ожидание API и итог -------------------------------------------
    Write-Step 9 $total 'Проверка сервера'
    $versionLine = 'dev'
    $versionFile = Join-Path $appDir 'VERSION.txt'
    if (Test-Path -LiteralPath $versionFile) {
        $versionLine = (Get-Content -LiteralPath $versionFile -TotalCount 1).Trim()
    }
    if ($NoService) {
        Write-Info '  режим -NoService: сервер не запущен; для запуска выполните:'
        Write-Info "    powershell -NoProfile -ExecutionPolicy Bypass -File `"$runScript`""
    } else {
        # Все маршруты сервера, включая /api/config, требуют Bearer-токен
        # владельца (проверено E2E: без токена сервер отвечает 401).
        $ready = $false
        for ($i = 0; $i -lt 15; $i++) {
            try {
                $tok = Read-OwnerToken -Dir $Dir
                $null = Invoke-NaApi -Uri "http://127.0.0.1:${serverPort}/api/config" -Token $tok -TimeoutSec 2
                $ready = $true
                break
            } catch {
                Start-Sleep -Seconds 2
            }
        }
        if (-not $ready) {
            Write-Fail "сервер не ответил за 30 секунд; журнал: $Dir\logs\server-err-*.log"
            throw 'сервер не отвечает на http://127.0.0.1:8484/api/config'
        }
        Write-Ok 'сервер отвечает на http://127.0.0.1:8484/api/config'
    }
    Write-NaLog -Dir $Dir -Name 'install' -Message 'шаг 9/9: установка завершена'

    Write-Host ''
    Write-Host '—————— ИТОГ ——————'
    Write-Host ("ОК: NetAtlas {0} установлен в {1} ({2} с)" -f $versionLine, $Dir, [int]$sw.Elapsed.TotalSeconds)
    Write-Host ("Адрес владельца: http://127.0.0.1:{0} (только этот компьютер)" -f $serverPort)
    Write-Host $clipboardNote
    Write-Host ("Логи: {0}\logs" -f $Dir)
    Write-Host 'Следующие шаги:'
    Write-Host '  сканирование: powershell -NoProfile -ExecutionPolicy Bypass -File "C:\NetAtlas\app\scripts\install\Start-NetAtlasScan.ps1"'
    Write-Host '  отчёт для аудитора: powershell -NoProfile -ExecutionPolicy Bypass -File "C:\NetAtlas\app\scripts\install\Get-NetAtlasReport.ps1"'
}
catch {
    Write-Fail $_.Exception.Message
    Write-NaLog -Dir $Dir -Name 'install' -Message ("ОШИБКА: {0}" -f $_.Exception.Message)
    exit 1
}
