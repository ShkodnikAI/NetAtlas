# Брандмауэр Windows (только чтение): состояние по профилям.
$profiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
if ($null -eq $profiles) { exit 0 }
$out = @($profiles | ForEach-Object {
    [pscustomobject]@{
        profile = [string]$_.Name
        enabled = [string]$_.Enabled
    }
})
[pscustomobject]@{ profiles = $out } | ConvertTo-Json -Compress -Depth 3
