# NetAtlas.Common — общие помощники скриптов установки (NR-028).
# Windows PowerShell 5.1 совместимо. Ничего не печатает само по себе;
# секреты в вывод не попадают никогда (маскирование — Get-MaskedText).
Set-StrictMode -Version 2.0

# --- вывод шагов ----------------------------------------------------------

function Write-Step {
    param([int]$Number, [int]$Total, [string]$Message)
    Write-Host "[$Number/$Total] $Message"
}

function Write-Ok {
    param([string]$Message)
    Write-Host "ОК: $Message"
}

function Write-Fail {
    param([string]$Message)
    Write-Host "ОШИБКА: $Message" -ForegroundColor Red
    Write-Host 'Что делать: исправьте причину и запустите скрипт снова (повторный запуск безопасен).' -ForegroundColor Red
}

function Write-Info {
    param([string]$Message)
    Write-Host $Message
}

# --- лог без секретов ------------------------------------------------------

function Write-NaLog {
    param([string]$Dir, [string]$Name, [string]$Message)
    $logDir = Join-Path $Dir 'logs'
    if (-not (Test-Path -LiteralPath $logDir)) {
        try { New-Item -ItemType Directory -Path $logDir -Force | Out-Null } catch { return }
    }
    $line = "{0} {1} {2}" -f (Get-Date -Format 'yyyy-MM-ddTHH:mm:ssK'), $Name, (Get-MaskedText -Text $Message)
    try {
        Add-Content -LiteralPath (Join-Path $logDir "$Name.log") -Value $line -Encoding UTF8 -ErrorAction Stop
    } catch { }
}

# --- маскирование секретов -------------------------------------------------

function Get-MaskedText {
    # Маскирует: Bearer-токены, пары «имя=значение» для паролей/токенов,
    # длинные base64url-токены (токен владельца: 43 символа base64url).
    # Ничего не расшифровывает и не печатает исходное значение.
    param([AllowEmptyString()][string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $Text }
    $out = $Text
    $out = [regex]::Replace($out, '(?i)bearer\s+[A-Za-z0-9._\-]+', 'Bearer [REDACTED]')
    $out = [regex]::Replace($out, '(?i)\b(password|passwd|pwd|token|secret|authorization)\b(\s*[=:]\s*)\S+', '$1$2[REDACTED]')
    $out = [regex]::Replace($out, '\b[A-Za-z0-9_\-]{43}\b', '[REDACTED]')
    return $out
}

# --- подсети ---------------------------------------------------------------

function ConvertTo-Cidr {
    # Адрес и длина префикса -> адрес сети в CIDR («192.168.1.57», 24 ->
    # «192.168.1.0/24»). Арифметика на long: без переполнений PS 5.1.
    param(
        [Parameter(Mandatory = $true)][string]$IPAddress,
        [Parameter(Mandatory = $true)][ValidateRange(0, 32)][int]$PrefixLength
    )
    $ip = $null
    if (-not [System.Net.IPAddress]::TryParse($IPAddress, [ref]$ip)) {
        throw "не IP-адрес: $IPAddress"
    }
    if ($ip.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
        throw "не IPv4-адрес: $IPAddress"
    }
    $b = $ip.GetAddressBytes()
    $addr = [long]$b[0] * 16777216 + [long]$b[1] * 65536 + [long]$b[2] * 256 + [long]$b[3]
    if ($PrefixLength -eq 0) {
        $mask = [long]0
    } else {
        $mask = ([long]4294967295 -shl (32 - $PrefixLength)) -band [long]4294967295
    }
    $net = $addr -band $mask
    $n = @(
        [byte](($net -shr 24) -band 255),
        [byte](($net -shr 16) -band 255),
        [byte](($net -shr 8) -band 255),
        [byte]($net -band 255)
    )
    return ('{0}.{1}.{2}.{3}/{4}' -f $n[0], $n[1], $n[2], $n[3], $PrefixLength)
}

function Test-VirtualAdapter {
    # $true — адаптер виртуальный (Hyper-V, Docker, VPN, WSL, TAP и т.п.)
    # по описанию; такие адаптеры не считаются подсетью владельца.
    param([AllowEmptyString()][string]$Description)
    if ([string]::IsNullOrWhiteSpace($Description)) { return $false }
    return ($Description -match 'Hyper-V|vEthernet|Docker|VPN|VirtualBox|VMware|Virtual\b|TAP-|TUN|WSL|Loopback|PANGP|GlobalProtect|OpenVPN|WireGuard|ZeroTier|Tailscale')
}

function Get-LanSubnets {
    # Активные IPv4-адаптеры со шлюзом -> CIDR; виртуальные исключаются.
    # Возвращает массив строк; пустой массив — ничего подходящего.
    $result = @()
    $ipcfgs = @(Get-NetIPConfiguration -ErrorAction SilentlyContinue | Where-Object { $_.IPv4DefaultGateway -and $_.IPv4Address })
    foreach ($c in $ipcfgs) {
        $desc = ''
        try { $desc = (Get-NetAdapter -InterfaceIndex $c.InterfaceIndex -ErrorAction Stop).InterfaceDescription } catch { }
        if (Test-VirtualAdapter -Description $desc) { continue }
        foreach ($a in @($c.IPv4Address)) {
            if ($null -eq $a) { continue }
            try {
                $cidr = ConvertTo-Cidr -IPAddress $a.IPAddress -PrefixLength $a.PrefixLength
                if ($result -notcontains $cidr) { $result += $cidr }
            } catch { }
        }
    }
    return ,$result
}

# --- токен владельца --------------------------------------------------------

function Save-OwnerToken {
    # Создаёт secrets\owner-token.txt (32 случайных байта, base64url);
    # существующий не меняет (повторный запуск ничего не ломает);
    # -RotateToken заменяет. Токен НЕ печатается. Возвращает $true,
    # если файл создан/заменён.
    param(
        [Parameter(Mandatory = $true)][string]$Dir,
        [switch]$Rotate
    )
    $path = Join-Path $Dir 'secrets\owner-token.txt'
    if ((Test-Path -LiteralPath $path) -and -not $Rotate) {
        return $false
    }
    $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
    $bytes = New-Object byte[] 32
    $rng.GetBytes($bytes)
    $rng.Dispose()
    $token = [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
    $text = $token + [Environment]::NewLine
    [IO.File]::WriteAllText($path, $text)
    return $true
}

# --- HTTP к серверу ---------------------------------------------------------

function Invoke-NaApi {
    # Вызов API владельца; PS 5.1: явно включаем TLS 1.2. Токен идёт
    # только в заголовок, в тело ошибок и вывод не попадает.
    param(
        [Parameter(Mandatory = $true)][string]$Uri,
        [ValidateSet('GET', 'POST')][string]$Method = 'GET',
        [string]$Token,
        [string]$JsonBody,
        [int]$TimeoutSec = 30
    )
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    } catch { }
    $params = @{ Method = $Method; Uri = $Uri; TimeoutSec = $TimeoutSec; ErrorAction = 'Stop' }
    if ($Token) {
        $params['Headers'] = @{ Authorization = "Bearer $Token" }
    }
    if ($JsonBody) {
        $params['Body'] = $JsonBody
        $params['ContentType'] = 'application/json'
    }
    return Invoke-RestMethod @params
}

function Read-OwnerToken {
    # Токен владельца из файла; без печати значения.
    param([Parameter(Mandatory = $true)][string]$Dir)
    $path = Join-Path $Dir 'secrets\owner-token.txt'
    if (-not (Test-Path -LiteralPath $path)) {
        throw "токен владельца не найден: $path (запустите Install-NetAtlas.ps1)"
    }
    return (Get-Content -LiteralPath $path -TotalCount 1).Trim()
}

# --- права каталогов --------------------------------------------------------

function Format-NaDeviceRows {
    <#
    .SYNOPSIS
        Строки таблицы найденных устройств из ответа GET /api/devices (NR-030).
    .DESCRIPTION
        Принимает массив устройств из поля .devices ответа и возвращает
        по строке на устройство: MAC, IP, вендор, имена, источники.
        MAC у хостов без MAC (id «ip:адрес») в ответе сервера содержит
        сам идентификатор — в таблицу он не попадает. Одиночные значения
        JSON (ConvertFrom-Json) разворачиваются в массивы, пустые
        пропускаются. Чистая функция: вывод проверяется Pester-тестом.
    #>
    param(
        [AllowEmptyCollection()]
        [object[]]$Devices
    )
    # Сервер не отдаёт пустые vendor/hostname/ssid (omitempty), а при
    # StrictMode обращение к отсутствующему свойству бросает исключение.
    $get = {
        param($o, [string]$n)
        $p = $o.PSObject.Properties[$n]
        if ($null -ne $p) { $p.Value } else { $null }
    }
    $rows = @()
    foreach ($d in @($Devices | Where-Object { $_ })) {
        $ips = @(& $get $d 'ips' | Where-Object { $_ }) -join ', '
        $names = @(& $get $d 'names' | Where-Object { $_ } | ForEach-Object { & $get $_ 'name' }) -join ', '
        $sources = @(& $get $d 'observations' | Where-Object { $_ } | ForEach-Object { & $get $_ 'source' } | Sort-Object -Unique) -join ','
        $mac = ''
        $rawMac = [string](& $get $d 'mac')
        if ($rawMac -and -not $rawMac.StartsWith('ip:')) { $mac = $rawMac }
        $vendor = [string](& $get $d 'vendor')
        $row = '{0}  {1}  {2}' -f $mac.PadRight(19), $ips.PadRight(16), $vendor.PadRight(22)
        if ($names) { $row += "  $names" }
        if ($sources) { $row += "  [$sources]" }
        $rows += $row
    }
    return $rows
}

function Protect-NetAtlasDir {
    # Закрывает каталог: только SYSTEM и администраторы, без
    # наследования. SIDs вместо имён: работает на любой локали
    # (*S-1-5-18 SYSTEM, *S-1-5-32-544 Администраторы).
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "каталог не найден: $Path"
    }
    & icacls $Path /inheritance:r | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "icacls /inheritance:r не прошёл: $Path" }
    & icacls $Path /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "icacls /grant не прошёл: $Path" }
}

Export-ModuleMember -Function Write-Step, Write-Ok, Write-Fail, Write-Info, Write-NaLog, Format-NaDeviceRows,
    Get-MaskedText, ConvertTo-Cidr, Test-VirtualAdapter, Get-LanSubnets,
    Save-OwnerToken, Invoke-NaApi, Read-OwnerToken, Protect-NetAtlasDir
