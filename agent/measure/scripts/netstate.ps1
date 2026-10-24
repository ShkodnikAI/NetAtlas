# Состояние машины для замеров (только чтение): шлюз по таблице
# маршрутов, загрузка CPU, счётчики адаптеров за 1 секунду.
$gw = (Get-NetRoute -DestinationPrefix 0.0.0.0/0 -ErrorAction SilentlyContinue |
    Sort-Object RouteMetric | Select-Object -First 1).NextHop
$cpu = (Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average
if ($null -eq $cpu) { $cpu = 0 }
$rx = 0.0; $tx = 0.0; $bps = 0.0
$adapters = @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' })
$rx1 = 0.0; $tx1 = 0.0
foreach ($a in $adapters) {
    $s = $a | Get-NetAdapterStatistics -ErrorAction SilentlyContinue
    if ($s) { $rx1 += [double]$s.ReceivedBytes; $tx1 += [double]$s.SentBytes }
    $spd = [double]$a.Speed
    if ($spd -gt $bps) { $bps = $spd }
}
Start-Sleep -Seconds 1
$rx2 = 0.0; $tx2 = 0.0
foreach ($a in $adapters) {
    $s = $a | Get-NetAdapterStatistics -ErrorAction SilentlyContinue
    if ($s) { $rx2 += [double]$s.ReceivedBytes; $tx2 += [double]$s.SentBytes }
}
$rx = $rx2 - $rx1
$tx = $tx2 - $tx1
[pscustomobject]@{
    gateway = [string]$gw
    cpuLoad = [double]$cpu
    rxBytes = $rx
    txBytes = $tx
    linkBps = $bps
} | ConvertTo-Json -Compress
