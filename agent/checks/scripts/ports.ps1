# Слушающие порты (только чтение): TCP-сокеты в состоянии Listen
# с именем процесса-владельца. Только список: владелец смотрит сам.
$conns = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue
if ($null -eq $conns) { exit 0 }
$names = @{}
$procs = Get-Process -ErrorAction SilentlyContinue
if ($null -ne $procs) {
    foreach ($p in $procs) { $names[[int]$p.Id] = [string]$p.ProcessName }
}
$out = @($conns | ForEach-Object {
    $proc = ''
    if ($names.ContainsKey([int]$_.OwningProcess)) { $proc = $names[[int]$_.OwningProcess] }
    [pscustomobject]@{
        localAddress = [string]$_.LocalAddress
        localPort    = [int]$_.LocalPort
        process      = $proc
    }
})
[pscustomobject]@{ ports = $out } | ConvertTo-Json -Compress -Depth 3
