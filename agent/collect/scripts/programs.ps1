# Установленные программы (только чтение): ключи Uninstall реестра.
# Записи без DisplayName пропускаются.
$paths = @(
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
$out = @(foreach ($p in $paths) {
    Get-ItemProperty -Path $p -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName } | ForEach-Object {
        [pscustomobject]@{ name = [string]$_.DisplayName; version = [string]$_.DisplayVersion; publisher = [string]$_.Publisher; installDate = [string]$_.InstallDate }
    }
})
[pscustomobject]@{ programs = $out } | ConvertTo-Json -Compress -Depth 3
