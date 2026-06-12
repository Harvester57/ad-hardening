# Get-DfsrHealthStatus.ps1
# Description: Checks the event logs for DFSR replication errors.

Write-Host "Checking DFSR replication event logs..." -ForegroundColor Cyan

$DfsrEvents = Get-WinEvent -LogName "DFS Replication" -MaxEvents 10 -ErrorAction SilentlyContinue

if ($DfsrEvents) {
    foreach ($Event in $DfsrEvents) {
        $EventColor = if ($Event.LevelDisplayName -eq "Error") { "Red" } else { "White" }
        Write-Host "[$($Event.TimeCreated)] [$($Event.LevelDisplayName)] ID: $($Event.Id) - $($Event.Message)" -ForegroundColor $EventColor
    }
} else {
    Write-Host "[+] No recent DFSR events or errors detected." -ForegroundColor Green
}
