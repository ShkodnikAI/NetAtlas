<#
.SYNOPSIS
    Сборка релиза NetAtlas для Windows (NR-027).
.DESCRIPTION
    Собирает все пять программ (GOOS=windows, GOARCH=amd64, CGO
    выключен) с зашитой версией и датой коммита, складывает архив
    netatlas-<версия>-windows-amd64.zip (bin\*.exe, docs\*.md,
    scripts\install\*.ps1 если есть, LICENSE, VERSION.txt) и файл
    SHA256SUMS.txt (хэш архива и всех файлов внутри). Публикацией не
    занимается: релиз создаёт workflow release.yml. Проверка того же
    архива — scripts/Verify-Release.ps1.
.EXAMPLE
    .\Build-Release.ps1 -Version v0.1.0 -OutDir dist
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^v\d+\.\d+\.\d+(-[0-9A-Za-z.\-]+)?$')]
    [string]$Version,

    [string]$OutDir = 'dist',

    # Дата коммита (RFC3339); по умолчанию — текущее время UTC.
    [string]$CommitDate = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
)

$ErrorActionPreference = 'Stop'

# Относительный -OutDir резолвится в абсолютный: дальше все пути
# считаются от него (и .NET-методы требуют абсолютные пути).
if (-not [IO.Path]::IsPathRooted($OutDir)) {
    $OutDir = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutDir)
}

# --- проверки окружения --------------------------------------------------

if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
    throw 'ОШИБКА: go не найден в PATH (нужен Go для сборки)'
}
$root = Split-Path -Parent $PSScriptRoot
$ldVersion = "github.com/ShkodnikAI/NetAtlas/internal/version.Version=$Version"
$ldCommit = "github.com/ShkodnikAI/NetAtlas/internal/version.CommitDate=$CommitDate"

$programs = @('netatlas-server', 'netatlas-agent', 'netatlas-agent-notify', 'netatlas-pki', 'netatlas-scan')

# Имена файлов, которых в архиве быть не должно (секреты/ключи/базы).
$secretNamePattern = '\.(key|pem|db|sqlite3?|env|pfx|p12|kdbx)$|(^|/)id_rsa|^\.env$|secret|token|credential'

# --- подготовка каталога сборки ------------------------------------------

$stage = Join-Path $OutDir 'stage'
$zipPath = Join-Path $OutDir ("netatlas-$Version-windows-amd64.zip")
$sumsPath = Join-Path $OutDir 'SHA256SUMS.txt'
if (Test-Path -LiteralPath $stage) {
    Remove-Item -LiteralPath $stage -Recurse -Force
}
New-Item -ItemType Directory -Path (Join-Path $stage 'bin') -Force | Out-Null

# --- сборка пяти программ -------------------------------------------------

$i = 0
foreach ($p in $programs) {
    $i++
    Write-Host "[$i/5] go build $p (windows/amd64, $Version, $CommitDate)"
    $env:GOOS = 'windows'
    $env:GOARCH = 'amd64'
    $env:CGO_ENABLED = '0'
    $out = Join-Path $stage "bin\$p.exe"
    & go build -trimpath -ldflags "-s -w $ldVersion $ldCommit" -o $out (Join-Path $root "cmd\$p")
    if ($LASTEXITCODE -ne 0) {
        throw "ОШИБКА: go build $p завершился с кодом $LASTEXITCODE"
    }
}
Remove-Item Env:GOOS, Env:GOARCH, Env:CGO_ENABLED -ErrorAction SilentlyContinue

# --- документация, лицензия, версия --------------------------------------

Write-Host 'Копирование docs, LICENSE, VERSION.txt, scripts/install (если есть)'
New-Item -ItemType Directory -Path (Join-Path $stage 'docs') -Force | Out-Null
Copy-Item -Path (Join-Path $root 'docs\*.md') -Destination (Join-Path $stage 'docs') -Force
$license = Join-Path $root 'LICENSE'
if (Test-Path -LiteralPath $license) {
    Copy-Item -LiteralPath $license -Destination $stage -Force
}
$installDir = Join-Path $root 'scripts\install'
if (Test-Path -LiteralPath $installDir) {
    New-Item -ItemType Directory -Path (Join-Path $stage 'scripts\install') -Force | Out-Null
    Copy-Item -Path (Join-Path $installDir '*.ps1') -Destination (Join-Path $stage 'scripts\install') -Force
    Copy-Item -Path (Join-Path $installDir 'README.md') -Destination (Join-Path $stage 'scripts\install') -Force -ErrorAction SilentlyContinue
}
[IO.File]::WriteAllText((Join-Path $stage 'VERSION.txt'), "$Version`n$CommitDate`n")

# --- запрет секретов в архиве --------------------------------------------

Write-Host 'Проверка листинга: в архиве нет ключей, баз, .env'
$suspicious = Get-ChildItem -Path $stage -Recurse -File |
    Where-Object { ($_.FullName.Substring($stage.Length + 1) -replace '\\', '/') -match $secretNamePattern }
if ($suspicious) {
    $names = ($suspicious | ForEach-Object { $_.FullName.Substring($stage.Length + 1) }) -join ', '
    throw "ОШИБКА: в архиве обнаружены запрещённые файлы: $names"
}

# --- архив и суммы --------------------------------------------------------

Write-Host "Архив: $zipPath"
if (Test-Path -LiteralPath $zipPath) {
    Remove-Item -LiteralPath $zipPath -Force
}
Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $zipPath -Force

Write-Host "Суммы: $sumsPath"
$lines = @()
$zipHash = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash.ToLowerInvariant()
$lines += "$zipHash  $(Split-Path -Leaf $zipPath)"
foreach ($f in (Get-ChildItem -Path $stage -Recurse -File | Sort-Object FullName)) {
    $rel = $f.FullName.Substring($stage.Length + 1) -replace '\\', '/'
    $h = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    $lines += "$h  $rel"
}
[IO.File]::WriteAllText($sumsPath, ($lines -join "`n") + "`n")

Write-Host ''
Write-Host "ОК: собран $zipPath"
Write-Host "ОК: суммы $sumsPath ($($lines.Count) строк)"
