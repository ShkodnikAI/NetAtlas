# Процессор, ОЗУ, плата, BIOS (только чтение).
$cs = Get-CimInstance Win32_ComputerSystem | Select-Object -First 1
$cpus = @(Get-CimInstance Win32_Processor | ForEach-Object {
    [pscustomobject]@{ name = [string]$_.Name; cores = [string]$_.NumberOfCores; logical = [string]$_.NumberOfLogicalProcessors; maxClockMHz = [string]$_.MaxClockSpeed }
})
$mem = @(Get-CimInstance Win32_PhysicalMemory | ForEach-Object {
    [pscustomobject]@{ slot = [string]$_.DeviceLocator; bank = [string]$_.BankLabel; capacity = [string]$_.Capacity; speedMHz = [string]$_.Speed; manufacturer = [string]$_.Manufacturer }
})
$bb = Get-CimInstance Win32_BaseBoard | Select-Object -First 1
$bios = Get-CimInstance Win32_BIOS | Select-Object -First 1
[pscustomobject]@{
    totalPhysicalMemory = [string]$cs.TotalPhysicalMemory
    cpus = $cpus
    memoryModules = $mem
    baseBoard = [pscustomobject]@{ manufacturer = [string]$bb.Manufacturer; product = [string]$bb.Product }
    bios = [pscustomobject]@{ manufacturer = [string]$bios.Manufacturer; version = [string]$bios.SMBIOSBIOSVersion; releaseDate = [string]$bios.ReleaseDate }
} | ConvertTo-Json -Compress -Depth 3
