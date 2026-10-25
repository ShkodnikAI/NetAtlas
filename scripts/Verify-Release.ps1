<#
.SYNOPSIS
    Проверка релиза NetAtlas (NR-027).
.DESCRIPTION
    Принимает путь к zip и к SHA256SUMS.txt: сверяет хэш архива,
    распаковывает во временную папку, сверяет хэши всех файлов из
    суммы, проверяет листинг (нет ключей, баз, .env) и запускает
    каждый .exe из bin с --version: все пять обязаны вывести
    «netatlas <версия>» из VERSION.txt. Ничего не пишет вне
    временной папки; временная папка удаляется.
.EXAMPLE
    .\Verify-Release.ps1 -ZipPath dist\netatlas-v0.1.0-windows-amd64.zip -SumsPath dist\SHA256SUMS.txt
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ZipPath,

    [Parameter(Mandatory = $true)]
    [string]$SumsPath,

    # Ожидаемая версия (например v0.1.0); если не задана — берётся
    # из VERSION.txt внутри архива.
    [string]$Version
)

$ErrorActionPreference = 'Stop'
$steps = @('хэш архива', 'хэши файлов архива', 'листинг без секретов', 'запуск --version всех программ')
$failed = @()

function Fail($step, $msg) {
    Write-Host "ОШИБКА [$step]: $msg"
    $script:failed += "$step"
}

# --- проверки входных файлов ---------------------------------------------

foreach ($f in @($ZipPath, $SumsPath)) {
    if (-not (Test-Path -LiteralPath $f)) {
        throw "ОШИБКА: файл не найден: $f"
    }
}
$sums = @{}
foreach ($line in (Get-Content -LiteralPath $SumsPath)) {
    if ($line -match '^([0-9a-fA-F]{64})\s\s?(.+)$') {
        $sums[$Matches[2] -replace '\\', '/'] = $Matches[1].ToLowerInvariant()
    }
}
if ($sums.Count -eq 0) {
    throw 'ОШИБКА: SHA256SUMS.txt пуст или в неверном формате (ожидается «<хэш>  <путь»)'
}

$tmp = Join-Path ([IO.Path]::GetTempPath()) ("netatlas-verify-" + [IO.Path]::GetRandomFileName())
Write-Host "[1/4] Хэш архива по SHA256SUMS.txt"

# --- 1. хэш архива --------------------------------------------------------

$zipName = Split-Path -Leaf $ZipPath
$zipHash = (Get-FileHash -LiteralPath $ZipPath -Algorithm SHA256).Hash.ToLowerInvariant()
if (-not $sums.ContainsKey($zipName)) {
    Fail $steps[0] "в SHA256SUMS.txt нет строки для $zipName"
}
elseif ($sums[$zipName] -ne $zipHash) {
    Fail $steps[0] "хэш архива не совпал: файл $zipHash, сумма $($sums[$zipName]) — архив не тот или повреждён"
}
else {
    Write-Host "ОК [$($steps[0])]: $zipName"
}

# --- 2. распаковка и хэши файлов -----------------------------------------

Write-Host "[2/4] Распаковка и сверка хэшей файлов"
Expand-Archive -LiteralPath $ZipPath -DestinationPath $tmp -Force
$mismatch = 0
$checked = 0
foreach ($rel in $sums.Keys) {
    if ($rel -eq $zipName) { continue }
    $checked++
    $p = Join-Path $tmp ($rel -replace '/', '\')
    if (-not (Test-Path -LiteralPath $p)) {
        Fail $steps[1] "файл из суммы отсутствует в архиве: $rel"
        continue
    }
    $h = (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($h -ne $sums[$rel]) {
        Fail $steps[1] "хэш не совпал: $rel"
        $mismatch++
    }
}
if ($mismatch -eq 0 -and $checked -gt 0) {
    Write-Host "ОК [$($steps[1])]: $checked файлов"
}

# --- 3. листинг без секретов ---------------------------------------------

Write-Host "[3/4] Листинг: нет ключей, баз, .env"
$secretNamePattern = '\.(key|pem|db|sqlite3?|env|pfx|p12|kdbx)$|(^|/)id_rsa|^\.env$|secret|token|credential'
$bad = Get-ChildItem -Path $tmp -Recurse -File |
    Where-Object { ($_.FullName.Substring($tmp.Length + 1) -replace '\\', '/') -match $secretNamePattern }
if ($bad) {
    Fail $steps[2] ('запрещённые файлы в архиве: ' + (($bad | ForEach-Object { $_.FullName.Substring($tmp.Length + 1) }) -join ', '))
}
else {
    Write-Host "ОК [$($steps[2])]"
}

# --- 4. VERSION.txt и запуск всех программ --------------------------------

Write-Host "[4/4] Запуск каждой программы с --version"
$versionFile = Join-Path $tmp 'VERSION.txt'
if (-not (Test-Path -LiteralPath $versionFile)) {
    Fail $steps[3] 'в архиве нет VERSION.txt'
}
else {
    $ver = (Get-Content -LiteralPath $versionFile -TotalCount 1 | Out-String).Trim()
    if ($Version -and $ver -ne $Version) {
        Fail $steps[3] "в VERSION.txt «$ver», ожидалось «$Version»"
    }
    $expected = "netatlas $ver"
    $exes = Get-ChildItem -Path (Join-Path $tmp 'bin') -Filter '*.exe' -ErrorAction SilentlyContinue
    if (-not $exes -or @($exes).Count -eq 0) {
        Fail $steps[3] 'в bin нет .exe файлов'
    }
    foreach ($exe in $exes) {
        # EAP=Continue на время запуска: потоки native-команды в PS 5.1
        # при EAP=Stop превращаются в ErrorRecord и бросают исключение.
        $ErrorActionPreference = 'Continue'
        $out = & $exe.FullName --version 2>&1
        $code = $LASTEXITCODE
        $ErrorActionPreference = 'Stop'
        $text = ($out | Out-String).Trim()
        if ($code -ne 0) {
            Fail $steps[3] "$($exe.Name) завершилась с кодом $code"
        }
        elseif ($text -ne $expected) {
            Fail $steps[3] "$($exe.Name) вывела «$text», ожидалось «$expected»"
        }
        else {
            Write-Host "ОК: $($exe.Name) → $text"
        }
    }
    $wanted = @('netatlas-server.exe', 'netatlas-agent.exe', 'netatlas-agent-notify.exe', 'netatlas-pki.exe', 'netatlas-scan.exe')
    foreach ($n in $wanted) {
        if (-not (Test-Path -LiteralPath (Join-Path $tmp "bin\$n"))) {
            Fail $steps[3] "в bin нет $n"
        }
    }
}

# --- итог -----------------------------------------------------------------

try {
    Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
}
catch { }

if ($failed.Count -gt 0) {
    Write-Host ''
    Write-Host "ОШИБКА: проверка релиза не пройдена ($($failed -join '; ')). Исправьте сборку и повторите."
    exit 1
}
Write-Host ''
Write-Host 'ОК: проверка релиза пройдена (хэши, листинг, --version всех пяти программ)'
