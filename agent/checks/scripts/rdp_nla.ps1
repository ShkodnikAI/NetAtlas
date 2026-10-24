# RDP и NLA (только чтение): включён ли удалённый рабочий стол и
# требует ли он проверку на уровне сети. Реестр читается, не пишется.
$deny = $null
try {
    $v = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -ErrorAction Stop
    $deny = [string]$v.fDenyTSConnections
} catch { }
$nla = $null
try {
    $v = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -ErrorAction Stop
    $nla = [string]$v.UserAuthentication
} catch { }
if ($null -eq $deny -and $null -eq $nla) { exit 0 }
[pscustomobject]@{
    rdpEnabled = $deny
    nlaRequired = $nla
} | ConvertTo-Json -Compress
