# Pester-тесты чистых функций NetAtlas.Common (NR-028) и страж
# локальной независимости команд icacls (issue #87).
# Запуск: Invoke-Pester -Path scripts/install/tests/NetAtlas.Common.Tests.ps1 -CI
# Только CI: Pester и PSScriptAnalyzer не устанавливаются на ПК владельца.

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..\NetAtlas.Common.psm1') -Force -DisableNameChecking
}

Describe 'ConvertTo-Cidr (адрес + префикс -> сеть)' {
    It '<addr>/<prefix> -> <expected>' -TestCases @(
        @{ addr = '192.168.1.57';  prefix = 24; expected = '192.168.1.0/24' }
        @{ addr = '10.1.130.5';    prefix = 23; expected = '10.1.130.0/23' }
        @{ addr = '10.1.131.5';    prefix = 23; expected = '10.1.130.0/23' }
        @{ addr = '192.168.5.77';  prefix = 22; expected = '192.168.4.0/22' }
        @{ addr = '172.16.1.2';    prefix = 30; expected = '172.16.1.0/30' }
        @{ addr = '172.16.1.6';    prefix = 30; expected = '172.16.1.4/30' }
        @{ addr = '192.168.1.5';   prefix = 32; expected = '192.168.1.5/32' }
        @{ addr = '10.0.0.1';      prefix = 0;  expected = '0.0.0.0/0' }
        @{ addr = '8.8.8.8';       prefix = 24; expected = '8.8.8.0/24' }
    ) {
        param($addr, $prefix, $expected)
        ConvertTo-Cidr -IPAddress $addr -PrefixLength $prefix | Should -Be $expected
    }

    It 'отказ на не-IPv4 и не-адресе' {
        { ConvertTo-Cidr -IPAddress 'не-адрес' -PrefixLength 24 } | Should -Throw
        { ConvertTo-Cidr -IPAddress '::1' -PrefixLength 24 } | Should -Throw
    }
}

Describe 'Test-VirtualAdapter (фильтр виртуальных адаптеров)' {
    It '<desc> -> <expected>' -TestCases @(
        @{ desc = 'Hyper-V Virtual Ethernet Adapter';            expected = $true }
        @{ desc = 'vEthernet (Default Switch)';                  expected = $true }
        @{ desc = 'Docker Desktop Virtual Ethernet Switch';      expected = $true }
        @{ desc = 'Wintun Userspace Tunnel';                     expected = $true }
        @{ desc = 'GlobalProtect';                               expected = $true }
        @{ desc = 'Microsoft Wi-Fi Direct Virtual Adapter';      expected = $true }
        @{ desc = 'Intel(R) Ethernet Connection I219-V';         expected = $false }
        @{ desc = 'Realtek PCIe GbE Family Controller';          expected = $false }
        @{ desc = 'Intel(R) Wi-Fi 6 AX201 160MHz';               expected = $false }
        @{ desc = '';                                            expected = $false }
    ) {
        param($desc, $expected)
        Test-VirtualAdapter -Description $desc | Should -Be $expected
    }
}

Describe 'Get-MaskedText (секреты не проходят в отчёт)' {
    It 'маскирует 43-символьный base64url-токен (токен владельца)' {
        # 32 байта -> base64url без padding = ровно 43 символа.
        $tok = ('abcdefghij' * 5).Substring(0, 43)
        $tok = $tok.Replace('+', '-').Replace('/', '_')
        $tok.Length | Should -Be 43
        $masked = Get-MaskedText -Text "ключ $tok конец"
        $masked | Should -Not -Match [regex]::Escape($tok)
        $masked | Should -Match '\[REDACTED\]'
    }
    It 'маскирует Bearer (формат маски не важен: исходник не проходит)' {
        $masked = Get-MaskedText -Text 'Authorization: Bearer eyJhbGciOi.example'
        $masked | Should -Not -Match [regex]::Escape('eyJhbGciOi.example')
        $masked | Should -Not -Match '(?i)bearer\s+eyJ'
        $masked | Should -Match '\[REDACTED\]'
    }
    It 'маскирует password= и token=' {
        Get-MaskedText -Text 'password=hunter2' | Should -Match 'password=\[REDACTED\]'
        # Значение собирается в рантайме: статические «token=<литерал>»
        # ловятся secret-scan'ом как фейковый ключ.
        $fake = 'token:' + 'abcdef' + '123456'
        Get-MaskedText -Text $fake | Should -Match 'token:\[REDACTED\]'
    }
    It 'обычный текст не меняется; маска стабильна при повторе' {
        Get-MaskedText -Text 'сервер запущен, устройство 192.168.1.5' | Should -Be 'сервер запущен, устройство 192.168.1.5'
        $once = Get-MaskedText -Text 'password=abc'
        Get-MaskedText -Text $once | Should -Be $once
    }
}

Describe 'Format-NaDeviceRows (разбор ответа /api/devices, NR-030)' {
    It 'устройство с MAC: адреса, имена и источники в одной строке' {
        $d = [pscustomobject]@{
            mac          = '02:00:00:00:00:02'
            ips          = @('10.0.0.2', '10.0.0.3')
            vendor       = 'Acme Corp'
            names        = @(
                [pscustomobject]@{ source = 'netbios'; name = 'pc-1'; seen = '2026-10-26T10:00:00Z' }
                [pscustomobject]@{ source = 'dns'; name = 'pc-1.lan'; seen = '2026-10-26T10:00:01Z' }
            )
            observations = @(
                [pscustomobject]@{ source = 'ping'; seen = 'x' }
                [pscustomobject]@{ source = 'arp'; seen = 'x' }
            )
        }
        $rows = @(Format-NaDeviceRows -Devices @($d))
        $rows.Count | Should -Be 1
        $rows[0] | Should -Match '02:00:00:00:00:02'
        $rows[0] | Should -Match '10\.0\.0\.2, 10\.0\.0\.3'
        $rows[0] | Should -Match 'Acme Corp'
        $rows[0] | Should -Match 'pc-1, pc-1\.lan'
        $rows[0] | Should -Match '\[arp,ping\]'
    }

    It 'ip:-хост: MAC пуст; одиночные значения JSON не режутся по символам' {
        # ConvertFrom-Json для одиночного элемента даёт скаляр, не массив.
        $d = [pscustomobject]@{
            mac          = 'ip:10.0.0.5'
            ips          = '10.0.0.5'
            vendor       = ''
            names        = [pscustomobject]@{ source = 'dns'; name = 'srv.lan'; seen = 'x' }
            observations = [pscustomobject]@{ source = 'ping'; seen = 'x' }
        }
        $rows = @(Format-NaDeviceRows -Devices $d)
        $rows.Count | Should -Be 1
        $rows[0] | Should -Match '10\.0\.0\.5'
        $rows[0] | Should -Not -Match 'ip:'
        $rows[0] | Should -Match 'srv\.lan'
        $rows[0] | Should -Match '\[ping\]'
    }

    It 'устройство без vendor и hostname (omitempty на сервере) не роняет таблицу при StrictMode' {
        $d = [pscustomobject]@{
            id = '02:00:00:00:00:09'; mac = '02:00:00:00:00:09'; ips = @('10.0.0.9')
            class = 'unknown'; names = @(); observations = @()
        }
        $rows = @(Format-NaDeviceRows -Devices $d)
        $rows.Count | Should -Be 1
        $rows[0] | Should -Match '10\.0\.0\.9'
    }

    It 'пустой и нулевой списки дают пустой результат' {
        @(Format-NaDeviceRows -Devices @()) | Should -HaveCount 0
        @(Format-NaDeviceRows -Devices $null) | Should -HaveCount 0
    }
}

Describe 'Save-OwnerToken (повторный запуск ничего не меняет)' {
    It 'создаёт токен, сохраняет при повторе, заменяет с -Rotate' {
        $dir = Join-Path $TestDrive 'na'
        New-Item -ItemType Directory -Path (Join-Path $dir 'secrets') -Force | Out-Null
        Save-OwnerToken -Dir $dir | Should -BeTrue
        $path = Join-Path $dir 'secrets\owner-token.txt'
        $first = (Get-Content -LiteralPath $path -TotalCount 1).Trim()
        $first.Length | Should -Be 43
        # повторный запуск: токен тот же
        Save-OwnerToken -Dir $dir | Should -BeFalse
        (Get-Content -LiteralPath $path -TotalCount 1).Trim() | Should -Be $first
        # -RotateToken: токен меняется
        Save-OwnerToken -Dir $dir -Rotate | Should -BeTrue
        (Get-Content -LiteralPath $path -TotalCount 1).Trim() | Should -Not -Be $first
    }
}

Describe 'Команды icacls: только SID, %USERNAME% и переменные (issue #87)' {
    # Страж локальной независимости: имена well-known учёток
    # локализованы (на русской Windows «Все», «Пользователи»,
    # «Администраторы»), поэтому /grant и /remove с именами падают
    # с ошибкой 1332 (PR #86 — агент, issue #87 — инструкция PKI.md).
    # Разрешены только SID (*S-1-…), подстановка %USERNAME% и
    # переменные PowerShell. Сканируются установочные скрипты
    # (без каталога tests: там имена допустимы в regex-проверках)
    # и команда из docs/PKI.md, которую владелец выполняет вручную.
    BeforeAll {
        $naRoot = (Get-Item (Join-Path $PSScriptRoot '..\..\..')).FullName
        $targets = @(Get-ChildItem -Path (Join-Path $naRoot 'scripts\install') -Recurse -Include *.ps1, *.psm1 -File |
            Where-Object { $_.FullName -notmatch '\\tests\\' })
        $pkiDoc = Join-Path $naRoot 'docs\PKI.md'
        if (Test-Path -LiteralPath $pkiDoc) { $targets += (Get-Item -LiteralPath $pkiDoc) }
    }

    It 'страж находит файлы для проверки (не ослеп)' {
        $targets.Count | Should -BeGreaterThan 0
    }

    It 'Protect-NetAtlasDir выдаёт права по SID S-1-5-18 и S-1-5-32-544' {
        $src = Get-Content -LiteralPath (Join-Path $naRoot 'scripts\install\NetAtlas.Common.psm1') -Raw
        ($src -match [regex]::Escape('*S-1-5-18:(OI)(CI)F')) | Should -BeTrue
        ($src -match [regex]::Escape('*S-1-5-32-544:(OI)(CI)F')) | Should -BeTrue
        # Имена групп в /grant и /remove не возвращаются.
        ($src -match 'icacls[^\r\n]*"(Everyone|BUILTIN\\(Users|Administrators))"') | Should -BeFalse
    }

    It 'в командах icacls скриптов и docs/PKI.md нет локализуемых имён учёток' {
        # Сегменты после /grant /deny /remove /replace — до следующего
        # флага, пайпа или конца строки. icacls учитывается только в
        # позиции команды (начало строки, после &, после пробела):
        # упоминания в строках-ошибках («icacls /grant не прошёл»)
        # проверять не нужно.
        $flagRe = '(?i)/(grant|deny|remove|replace)(?::[rgb])?(?<seg>.*?)(?=\s/|\s*\||$)'
        $icaclsRe = '(?i)(^|[\s&])icacls\s'
        $bad = @()
        foreach ($f in $targets) {
            $inHelp = $false
            $ln = 0
            foreach ($line in (Get-Content -LiteralPath $f.FullName)) {
                $ln++
                $t = $line.Trim()
                if ($t -match '^<#') { $inHelp = $true }
                if ($inHelp) { if ($t -match '#>') { $inHelp = $false }; continue }
                if ($t.StartsWith('#')) { continue }
                if ($line -notmatch $icaclsRe) { continue }
                foreach ($m in [regex]::Matches($line, $flagRe)) {
                    foreach ($tok in ($m.Groups['seg'].Value -split '\s+')) {
                        if ($tok -eq '') { continue }
                        $v = $tok.Trim("'`"")
                        if ($v -eq '') { continue }
                        $acct = ($v -split ':')[0]
                        $ok = ($acct -match '^\*?S-1-\d+(-\d+)*$') -or ($acct -ieq '%USERNAME%') -or ($acct.StartsWith('$'))
                        if (-not $ok) { $bad += ('{0}:{1}: {2}' -f $f.Name, $ln, $tok) }
                    }
                }
            }
        }
        if ($bad.Count -gt 0) { $bad | ForEach-Object { Write-Host "  НАРУШЕНИЕ: $_" } }
        $bad.Count | Should -Be 0
    }
}
