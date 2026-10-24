# Сетевые адаптеры (только чтение): MAC, IPv4, скорость линка.
$out = @(Get-NetAdapter -ErrorAction SilentlyContinue | ForEach-Object {
    $a = $_
    $ips = @(Get-NetIPAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object { [string]$_.IPAddress })
    [pscustomobject]@{ name = [string]$a.Name; description = [string]$a.InterfaceDescription; mac = [string]$a.MacAddress; linkSpeed = [string]$a.LinkSpeed; status = [string]$a.Status; ipv4 = $ips }
})
[pscustomobject]@{ adapters = $out } | ConvertTo-Json -Compress -Depth 3
