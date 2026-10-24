# Microsoft Defender (только чтение): состояние защиты в реальном
# времени. Командлета нет (сторонний антивирус, отключённая служба) —
# пустой вывод: «не определено», а не «безопасно».
$st = Get-MpComputerStatus -ErrorAction SilentlyContinue
if ($null -eq $st) { exit 0 }
[pscustomobject]@{
    antivirusEnabled = [string]$st.AntivirusEnabled
    realtimeEnabled  = [string]$st.RealTimeProtectionEnabled
    behaviorEnabled  = [string]$st.BehaviorMonitorEnabled
} | ConvertTo-Json -Compress
