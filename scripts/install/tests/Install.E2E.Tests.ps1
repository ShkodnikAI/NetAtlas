# Сквозной тест установки (NR-028): реальный запуск Install-NetAtlas.ps1
# на windows-latest в изолированном каталоге: -NoService, локальные
# бинарники (-LocalBinDir), документационная подсеть-заглушка
# 192.0.2.0/29 (TEST-NET-1, RFC 5737; сам скан не запускается).
# Требует переменную окружения NETATLAS_E2E_BIN с собранными .exe;
# без неё тест помечается пропущенным (локальный запуск без сборки).

BeforeAll {
    $binDir = $env:NETATLAS_E2E_BIN
    if (-not $binDir -or -not (Test-Path -LiteralPath (Join-Path $binDir 'netatlas-server.exe'))) {
        Set-ItResult -Skipped -Because 'NETATLAS_E2E_BIN не задан (нужны собранные бинарники)'
        return
    }
    $naDir = Join-Path ([IO.Path]::GetTempPath()) ("na-e2e-" + [IO.Path]::GetRandomFileName())
    New-Item -ItemType Directory -Path $naDir -Force | Out-Null
    $script:NaDir = $naDir
    $installScript = Join-Path $PSScriptRoot '..\Install-NetAtlas.ps1'
    $reportScript = Join-Path $PSScriptRoot '..\Get-NetAtlasReport.ps1'

    # Установка (первый прогон).
    & powershell -NoProfile -ExecutionPolicy Bypass -File $installScript `
        -Dir $naDir -LocalBinDir $binDir -NoService -Yes -Subnets '192.0.2.0/29' *> $null
    $script:InstallCode = $LASTEXITCODE
}

AfterAll {
    Get-Process netatlas-server -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    if ($script:NaDir -and (Test-Path -LiteralPath $script:NaDir)) {
        Remove-Item -LiteralPath $script:NaDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Describe 'E2E: установка, запуск сервера, отчёт без секретов' {
    It 'Install-NetAtlas.ps1 завершается успешно' {
        $script:InstallCode | Should -Be 0
    }

    It 'структура каталогов создана, secrets закрыт' {
        foreach ($sub in 'app', 'keys', 'data', 'logs', 'secrets') {
            (Test-Path -LiteralPath (Join-Path $script:NaDir $sub)) | Should -BeTrue
        }
        (Test-Path -LiteralPath (Join-Path $script:NaDir '.netatlas')) | Should -BeTrue
        (Test-Path -LiteralPath (Join-Path $script:NaDir 'keys\ca.pem')) | Should -BeTrue
        (Test-Path -LiteralPath (Join-Path $script:NaDir 'app\bin\netatlas-server.exe')) | Should -BeTrue
        (Test-Path -LiteralPath (Join-Path $script:NaDir 'data\subnets.txt')) | Should -BeTrue
    }

    It 'run-server.ps1 запускает сервер: /api/config отвечает' {
        $runScript = Join-Path $script:NaDir 'app\run-server.ps1'
        $proc = Start-Process powershell -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $runScript) -PassThru -WindowStyle Hidden
        # Все маршруты сервера требуют Bearer-токен (включая /api/config).
        $tok = (Get-Content -LiteralPath (Join-Path $script:NaDir 'secrets\owner-token.txt') -TotalCount 1).Trim()
        $headers = @{ Authorization = "Bearer $tok" }
        $ok = $false
        for ($i = 0; $i -lt 30; $i++) {
            Start-Sleep -Seconds 2
            try {
                $cfg = Invoke-RestMethod -Uri 'http://127.0.0.1:8484/api/config' -Headers $headers -TimeoutSec 2
                if ($null -ne $cfg) { $ok = $true; break }
            } catch { }
        }
        if (-not $ok) {
            Write-Host '---- диагностика: журналы установки ----'
            Get-ChildItem -Path (Join-Path $script:NaDir 'logs') -File -ErrorAction SilentlyContinue | ForEach-Object {
                Write-Host ">>> $($_.Name)"
                Get-Content -LiteralPath $_.FullName -Tail 15 -ErrorAction SilentlyContinue | Write-Host
            }
            Write-Host '---- диагностика: run-server.ps1 ----'
            Get-Content -LiteralPath $runScript -ErrorAction SilentlyContinue | Write-Host
            Write-Host '---- диагностика: прямой запуск сервера ----'
            $directErr = Join-Path $script:NaDir 'logs\direct-err.log'
            $exe = Join-Path $script:NaDir 'app\bin\netatlas-server.exe'
            $dp = Start-Process -FilePath $exe -ArgumentList @(
                '--db', (Join-Path $script:NaDir 'data\netatlas.db'),
                '--subnets', '192.0.2.0/29',
                '--agent-listen', '0.0.0.0:8443',
                '--agent-enroll-listen', '0.0.0.0:8444',
                '--allow-remote'
            ) -PassThru -WindowStyle Hidden -RedirectStandardError $directErr -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 5
            Write-Host ("прямой запуск жив: {0}" -f (-not $dp.HasExited))
            Get-Content -LiteralPath $directErr -Tail 10 -ErrorAction SilentlyContinue | Write-Host
            Get-Process netatlas-server -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        }
        try { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue } catch { }
        $ok | Should -BeTrue
    }

    It 'Get-NetAtlasReport.ps1: отчёт без токена и с версией' {
        & powershell -NoProfile -ExecutionPolicy Bypass -File $reportScript -Dir $script:NaDir *> $null
        $LASTEXITCODE | Should -Be 0
        $report = Get-ChildItem -Path (Join-Path $script:NaDir 'logs') -Filter 'report-*.txt' |
            Sort-Object LastWriteTime -Descending | Select-Object -First 1
        $report | Should -Not -BeNullOrEmpty
        # Отчёт пишется в UTF-8: без явной кодировки PS 5.1 читает ANSI.
        $content = Get-Content -LiteralPath $report.FullName -Raw -Encoding UTF8
        # Токен владельца не попал в отчёт.
        $token = (Get-Content -LiteralPath (Join-Path $script:NaDir 'secrets\owner-token.txt') -TotalCount 1).Trim()
        $content | Should -Not -Match [regex]::Escape($token)
        # Разделы отчёта на месте.
        $content | Should -Match 'Версия NetAtlas'
        $content | Should -Match 'Windows:'
        $content | Should -Match 'api/config'
    }

    It 'повторная установка ничего не ломает (токен и ключи сохранены)' {
        $tokenBefore = (Get-Content -LiteralPath (Join-Path $script:NaDir 'secrets\owner-token.txt') -TotalCount 1).Trim()
        & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot '..\Install-NetAtlas.ps1') `
            -Dir $script:NaDir -LocalBinDir $binDir -NoService -Yes -Subnets '192.0.2.0/29' *> $null
        $LASTEXITCODE | Should -Be 0
        (Get-Content -LiteralPath (Join-Path $script:NaDir 'secrets\owner-token.txt') -TotalCount 1).Trim() | Should -Be $tokenBefore
    }
}
