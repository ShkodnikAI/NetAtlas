# Подписанные драйверы (только чтение): устройство, производитель,
# версия, дата. Записи без имени устройства пропускаются.
$out = @(Get-CimInstance Win32_PnPSignedDriver -ErrorAction SilentlyContinue | Where-Object { $_.DeviceName } | ForEach-Object {
    [pscustomobject]@{ deviceName = [string]$_.DeviceName; manufacturer = [string]$_.Manufacturer; driverVersion = [string]$_.DriverVersion; driverDate = [string]$_.DriverDate }
})
[pscustomobject]@{ drivers = $out } | ConvertTo-Json -Compress -Depth 3
