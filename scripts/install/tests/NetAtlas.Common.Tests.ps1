# Pester-тесты чистых функций NetAtlas.Common (NR-028).
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
        @{ addr = '8.8.8.8';       prefix = 24; expected = '8.8.0.0/24' }
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
        $tok = 'ABH-3f9kQ2vX7_l1mN0pR4sT6uW8yZaBcDdEeFfGgHhI'
        ($tok.Length | Should -Be 43)
        $masked = Get-MaskedText -Text "ключ $tok конец"
        $masked | Should -Not -Match [regex]::Escape($tok)
        $masked | Should -Match '\[REDACTED\]'
    }
    It 'маскирует Bearer' {
        Get-MaskedText -Text 'Authorization: Bearer eyJhbGciOi.example' | Should -Match 'Bearer \[REDACTED\]'
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
