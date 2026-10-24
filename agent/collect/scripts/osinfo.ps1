# ОС и обновления (только чтение). Скаляры — строками: локаль не
# влияет на разбор.
$os = Get-CimInstance Win32_OperatingSystem | Select-Object -First 1
$hf = @(Get-HotFix -ErrorAction SilentlyContinue | Sort-Object InstalledOn | ForEach-Object {
    [pscustomobject]@{ id = [string]$_.HotFixID; description = [string]$_.Description; installedOn = [string]$_.InstalledOn }
})
[pscustomobject]@{
    caption        = [string]$os.Caption
    version        = [string]$os.Version
    buildNumber    = [string]$os.BuildNumber
    architecture   = [string]$os.OSArchitecture
    lastBootUpTime = [string]$os.LastBootUpTime
    hotfixes       = $hf
} | ConvertTo-Json -Compress -Depth 3
