<#
.SYNOPSIS
    Статические проверки скрипта на стенде (NR-026).
.DESCRIPTION
    Запускает PSScriptAnalyzer на скрипт и записывает JSON результат
    для отправки на сервер (POST /api/test-runs, stage=static).
    Не требует Hyper-V и прав администратора: чистый анализ текста.
.EXAMPLE
    .\Invoke-StaticCheck.ps1 -ScriptPath .\script.ps1 -Token <токен>
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)]
    [string]$ScriptPath,
    [string]$ServerUrl = 'http://127.0.0.1:8484',
    [string]$Token
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $ScriptPath)) {
    throw "Скрипт не найден: $ScriptPath"
}
$scriptSha = (Get-FileHash -LiteralPath $ScriptPath -Algorithm SHA256).Hash.ToLowerInvariant()

if (-not (Get-Module -ListAvailable PSScriptAnalyzer)) {
    Write-Warning "PSScriptAnalyzer не установлен: Install-Module PSScriptAnalyzer -Scope CurrentUser"
    return
}
Import-Module PSScriptAnalyzer

$findings = Invoke-ScriptAnalyzer -Path $ScriptPath -Severity Error, Warning
$errors = @($findings | Where-Object { $_.Severity -eq 'Error' })

$result = [ordered]@{
    script_sha256 = $scriptSha
    stage = 'static'
    result = if ($errors.Count -eq 0) { 'pass' } else { 'fail' }
    metrics = @{}
    log = ($findings | ForEach-Object {
        "{0} {1}:{2} {3}: {4}" -f $_.Severity, $_.Line, $_.Column, $_.RuleName, $_.Message
    }) -join "`n"
    ran_at = (Get-Date).ToUniversalTime().ToString('o')
}

$outFile = Join-Path (Split-Path -Parent $ScriptPath) ("static-result-" + (Get-Date -Format 'yyyyMMdd-HHmmss') + ".json")
$result | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $outFile -Encoding UTF8
Write-Host "Статических ошибок: $($errors.Count), предупреждений: $(@($findings).Count - $errors.Count)"
Write-Host "Результат: $outFile"

if ($Token) {
    # Отправка результата на сервер — изменяющее действие: только без -WhatIf.
    if (-not $PSCmdlet.ShouldProcess($ServerUrl, 'Отправить результат статической проверки')) {
        Write-Warning "Режим -WhatIf: результат только в файл, на сервер не отправлен."
        return
    }
    $headers = @{ Authorization = "Bearer $Token" }
    $body = @{
        script_sha256 = $scriptSha
        stage = 'static'
        result = $result.result
        log = $result.log
    }
    try {
        Invoke-RestMethod -Method Post -Uri "$ServerUrl/api/test-runs" -Headers $headers -Body ($body | ConvertTo-Json) -ContentType 'application/json' | Out-Null
        Write-Host "Результат отправлен на сервер."
    }
    catch {
        Write-Warning "Не удалось отправить на сервер: $($_.Exception.Message)"
    }
}
