# Диски и тома (только чтение). Износ/температура SSD — если диск
# отдаёт счётчики надёжности, иначе поля null (в отчёте отсутствуют).
$disks = @(Get-PhysicalDisk -ErrorAction SilentlyContinue | ForEach-Object {
    $d = $_
    $rel = $null
    try { $rel = $d | Get-StorageReliabilityCounter -ErrorAction SilentlyContinue } catch { $rel = $null }
    $wear = $null
    if ($rel -and $null -ne $rel.Wear) { $wear = [string]$rel.Wear }
    $temp = $null
    if ($rel -and $null -ne $rel.Temperature) { $temp = [string]$rel.Temperature }
    [pscustomobject]@{ friendlyName = [string]$d.FriendlyName; serial = [string]$d.SerialNumber; mediaType = [string]$d.MediaType; busType = [string]$d.BusType; size = [string]$d.Size; health = [string]$d.HealthStatus; wear = $wear; temperature = $temp }
})
$vols = @(Get-Volume -ErrorAction SilentlyContinue | Where-Object { $_.DriveLetter } | ForEach-Object {
    [pscustomobject]@{ driveLetter = [string]$_.DriveLetter; label = [string]$_.FileSystemLabel; fileSystem = [string]$_.FileSystem; driveType = [string]$_.DriveType; size = [string]$_.Size; sizeRemaining = [string]$_.SizeRemaining }
})
[pscustomobject]@{ disks = $disks; volumes = $vols } | ConvertTo-Json -Compress -Depth 4
