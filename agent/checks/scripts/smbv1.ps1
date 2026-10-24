# SMBv1 (только чтение): включён ли протокол SMB 1.0 на сервере.
# Командлета нет или отказ в доступе — пустой вывод: статус «не
# определено», а не «безопасно».
$cfg = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
if ($null -eq $cfg) { exit 0 }
[pscustomobject]@{
    enabled = [string]$cfg.EnableSMB1Protocol
} | ConvertTo-Json -Compress
