# Шифрование дисков BitLocker (только чтение): статус защиты томов.
# На редакциях без BitLocker командлета нет — пустой вывод.
$vols = Get-BitLockerVolume -ErrorAction SilentlyContinue
if ($null -eq $vols) { exit 0 }
$out = @($vols | ForEach-Object {
    [pscustomobject]@{
        mountPoint       = [string]$_.MountPoint
        protectionStatus = [string]$_.ProtectionStatus
        volumeStatus     = [string]$_.VolumeStatus
    }
})
[pscustomobject]@{ volumes = $out } | ConvertTo-Json -Compress -Depth 3
