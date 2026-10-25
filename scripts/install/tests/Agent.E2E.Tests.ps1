# Сквозной тест подключения агента (NR-029) на windows-latest:
# сервер запускается как в E2E NR-028, New-AgentInvite.ps1 собирает
# приглашение с локальным адресом, Install-Agent.ps1 -NoService -Yes
# регистрирует агента в изолированном каталоге, негативные тесты
# безопасности (просроченный токен, повторное использование, следы
# токена, права папки, раздатчик). Служба и права SYSTEM в CI не
# проверяются — это список для владельца.
# Требует NETATLAS_E2E_BIN (собранные .exe); иначе тесты пропускаются.

BeforeAll {
    $binDir = $env:NETATLAS_E2E_BIN
    if (-not $binDir -or -not (Test-Path -LiteralPath (Join-Path $binDir 'netatlas-server.exe'))) {
        Set-ItResult -Skipped -Because 'NETATLAS_E2E_BIN не задан'
        return
    }
    $script:NaDir = Join-Path ([IO.Path]::GetTempPath()) ("na-agent-" + [IO.Path]::GetRandomFileName())
    New-Item -ItemType Directory -Path $script:NaDir -Force | Out-Null
    # Изолированный каталог агента (не ProgramData).
    $script:AgentDir = Join-Path $script:NaDir 'agent-state'

    # Установка сервера и запуск (как в E2E NR-028).
    & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot '..\Install-NetAtlas.ps1') `
        -Dir $script:NaDir -LocalBinDir $binDir -NoService -Yes -Subnets '192.0.2.0/29' *> $null
    if ($LASTEXITCODE -ne 0) { throw 'установка сервера для E2E агента не удалась' }
    Start-Process powershell -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (Join-Path $script:NaDir 'app\run-server.ps1')) -WindowStyle Hidden | Out-Null
    $script:OwnerToken = (Get-Content -LiteralPath (Join-Path $script:NaDir 'secrets\owner-token.txt') -TotalCount 1).Trim()
    $headers = @{ Authorization = "Bearer $($script:OwnerToken)" }
    $ok = $false
    for ($i = 0; $i -lt 30; $i++) {
        Start-Sleep -Seconds 2
        try {
            $null = Invoke-RestMethod -Uri 'http://127.0.0.1:8484/api/config' -Headers $headers -TimeoutSec 2
            $ok = $true
            break
        } catch { }
    }
    if (-not $ok) { throw 'сервер не ответил на /api/config' }

    # Приглашение с локальным адресом (автоопределение отключено).
    & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot '..\New-AgentInvite.ps1') `
        -Dir $script:NaDir -ComputerName e2e-pc -Address 127.0.0.1 -Yes *> $null
    if ($LASTEXITCODE -ne 0) { throw 'New-AgentInvite.ps1 завершился с ошибкой' }
    $script:InviteDir = Get-ChildItem -LiteralPath (Join-Path $script:NaDir 'invites') -Directory |
        Sort-Object Name -Descending | Select-Object -First 1
    $script:EnrollToken = (Get-Content -LiteralPath (Join-Path $script:InviteDir.FullName 'invite.json') -Raw -Encoding UTF8 | ConvertFrom-Json).token
}

AfterAll {
    Get-Process netatlas-server -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot '..\Uninstall-Agent.ps1') -Confirm *> $null
    foreach ($d in @($script:NaDir, $script:AgentDir)) {
        if ($d -and (Test-Path -LiteralPath $d)) {
            Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

Describe 'E2E агент: приглашение, установка, негативные тесты безопасности' {
    It 'папка приглашения собрана и закрыта правами (нет Everyone, есть SYSTEM/администраторы)' {
        $d = $script:InviteDir.FullName
        (Test-Path -LiteralPath (Join-Path $d 'netatlas-agent.exe')) | Should -BeTrue
        (Test-Path -LiteralPath (Join-Path $d 'ca.pem')) | Should -BeTrue
        (Test-Path -LiteralPath (Join-Path $d 'Install-Agent.ps1')) | Should -BeTrue
        (Test-Path -LiteralPath (Join-Path $d 'invite.json')) | Should -BeTrue
        (Test-Path -LiteralPath "$d.zip") | Should -BeTrue
        $acl = icacls $d
        ($acl -join "`n") | Should -Match 'S-1-5-18|SYSTEM'
        ($acl -join "`n") | Should -Match 'S-1-5-32-544|Administrators'
        ($acl -join "`n") | Should -Not -Match 'Everyone|S-1-1-0'
        ($acl -join "`n") | Should -Not -Match 'BUILTIN\\Пользователи|BUILTIN\\Users'
    }

    It 'раздатчик выключен по умолчанию (порт 8765 закрыт)' {
        $addr = '127.0.0.1'
        $t = Test-NetConnection -ComputerName $addr -Port 8765 -WarningAction SilentlyContinue
        $t.TcpTestSucceeded | Should -BeFalse
    }

    It 'приглашение с просроченным токеном отвергается до запроса к серверу' {
        $expired = Join-Path $script:NaDir 'invites\expired'
        New-Item -ItemType Directory -Path $expired -Force | Out-Null
        Copy-Item -Path (Join-Path $script:InviteDir.FullName '*') -Destination $expired -Force -Exclude 'invite.json'
        Copy-Item -LiteralPath (Join-Path $script:InviteDir.FullName 'invite.json') -Destination $expired -Force
        $inv = Get-Content -LiteralPath (Join-Path $expired 'invite.json') -Raw -Encoding UTF8 | ConvertFrom-Json
        $inv.expires_at = '2020-01-01T00:00:00Z'
        [IO.File]::WriteAllText((Join-Path $expired 'invite.json'), ($inv | ConvertTo-Json))
        & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $expired 'Install-Agent.ps1') -NoService -Yes *> $null
        $LASTEXITCODE | Should -Be 1
    }

    It 'Install-Agent.ps1 -NoService -Yes: агент регистрируется, сервер его видит' {
        $env:NETATLAS_AGENT_DIR = $script:AgentDir
        & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $script:InviteDir.FullName 'Install-Agent.ps1') -NoService -Yes *> $null
        $LASTEXITCODE | Should -Be 0
        $headers = @{ Authorization = "Bearer $($script:OwnerToken)" }
        $agents = Invoke-RestMethod -Uri 'http://127.0.0.1:8484/api/agents' -Headers $headers -TimeoutSec 10
        @($agents.agents).Count | Should -BeGreaterOrEqual 1
    }

    It 'после установки на диске нет токена (каталог агента, логи, папка приглашения)' {
        $script:EnrollToken | Should -Not -BeNullOrEmpty
        $targets = @($script:AgentDir, $script:InviteDir.FullName, (Join-Path $script:NaDir 'logs'))
        foreach ($t in $targets) {
            if (-not (Test-Path -LiteralPath $t)) { continue }
            $files = Get-ChildItem -LiteralPath $t -Recurse -File -ErrorAction SilentlyContinue
            foreach ($f in $files) {
                $text = ''
                try { $text = [IO.File]::ReadAllText($f.FullName) } catch { continue }
                $text | Should -Not -Match ([regex]::Escape($script:EnrollToken)) -Because $f.FullName
            }
        }
        (Test-Path -LiteralPath (Join-Path $script:InviteDir.FullName 'invite.json')) | Should -BeFalse
    }

    It 'повторное использование токена отвергается сервером' {
        $env:NETATLAS_AGENT_DIR = Join-Path $script:NaDir 'agent-state-2'
        & (Join-Path $script:InviteDir.FullName 'netatlas-agent.exe') enroll `
            --server 'https://127.0.0.1:8443' --token $script:EnrollToken `
            --ca (Join-Path $script:InviteDir.FullName 'ca.pem') *> $null
        $LASTEXITCODE | Should -Not -Be 0
        Remove-Item Env:NETATLAS_AGENT_DIR -ErrorAction SilentlyContinue
    }

    It 'Get-AgentReport.ps1: отчёт без секретов, с checkin-полем' {
        $env:NETATLAS_AGENT_DIR = $script:AgentDir
        $env:NETATLAS_AGENT_EXE = Join-Path $script:InviteDir.FullName 'netatlas-agent.exe'
        & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot '..\Get-AgentReport.ps1') *> $null
        $LASTEXITCODE | Should -Be 0
        $report = Get-ChildItem -Path $env:TEMP -Filter 'netatlas-agent-report-*.txt' |
            Sort-Object LastWriteTime -Descending | Select-Object -First 1
        $report | Should -Not -BeNullOrEmpty
        $content = Get-Content -LiteralPath $report.FullName -Raw -Encoding UTF8
        # Контрольные значения: токен регистрации, токен владельца — не в отчёте.
        $content | Should -Not -Match ([regex]::Escape($script:EnrollToken))
        $content | Should -Not -Match ([regex]::Escape($script:OwnerToken))
        $content | Should -Match 'Очередь неслитых отчётов'
        $content | Should -Match 'checkin'
        Remove-Item Env:NETATLAS_AGENT_DIR, Env:NETATLAS_AGENT_EXE -ErrorAction SilentlyContinue
    }

    It 'раздатчик (-Serve): включён только явно, живёт ограниченное время, отдаёт один архив' {
        # Отдельное приглашение (новый одноразовый токен) с раздатчиком.
        $serveProc = Start-Process powershell -ArgumentList @(
            '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (Join-Path $PSScriptRoot '..\New-AgentInvite.ps1'),
            '-Dir', $script:NaDir, '-ComputerName', 'serve-test', '-Address', '127.0.0.1', '-Yes', '-Serve', '-ServeSeconds', '40'
        ) -PassThru -WindowStyle Hidden
        try {
            # Порт открывается после сборки папки (~секунды).
            $addr = '127.0.0.1'
            $up = $false
            for ($i = 0; $i -lt 30; $i++) {
                Start-Sleep -Seconds 1
                $t = Test-NetConnection -ComputerName $addr -Port 8765 -WarningAction SilentlyContinue
                if ($t.TcpTestSucceeded) { $up = $true; break }
            }
            $up | Should -BeTrue
            $serveInvite = Get-ChildItem -LiteralPath (Join-Path $script:NaDir 'invites') -Directory |
                Where-Object Name -like 'serve-test-*' | Select-Object -First 1
            $zipName = (Split-Path -Leaf $serveInvite.FullName) + '.zip'
            $dst = Join-Path $script:NaDir 'serve-download.zip'
            Invoke-WebRequest -Uri "http://127.0.0.1:8765/$zipName" -OutFile $dst -TimeoutSec 20
            (Get-Item -LiteralPath $dst).Length | Should -BeGreaterThan 1000
            # Один архив: после первой отдачи раздатчик закрыт — второй
            # запрос не проходит.
            Start-Sleep -Seconds 2
            { Invoke-WebRequest -Uri "http://127.0.0.1:8765/$zipName" -TimeoutSec 5 } | Should -Throw
        }
        finally {
            try { Stop-Process -Id $serveProc.Id -Force -ErrorAction SilentlyContinue } catch { }
            Get-Process netatlas-agent -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        }
    }

    It 'Uninstall-Agent.ps1 удаляет службу-состояние и каталог (с -Confirm)' {
        $env:NETATLAS_AGENT_DIR = $script:AgentDir
        & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot '..\Uninstall-Agent.ps1') -Confirm *> $null
        $LASTEXITCODE | Should -Be 0
        (Test-Path -LiteralPath $script:AgentDir) | Should -BeFalse
        Remove-Item Env:NETATLAS_AGENT_DIR -ErrorAction SilentlyContinue
    }
}
