# Get-DfsrHealthStatus.ps1
# Description: Checks the event logs for DFSR replication errors.

Write-Host "Checking DFSR replication event logs..." -ForegroundColor Cyan

$DfsrEvents = Get-WinEvent -LogName "DFS Replication" -MaxEvents 10 -ErrorAction SilentlyContinue

if ($DfsrEvents) {
    foreach ($DfsrEvent in $DfsrEvents) {
        $EventColor = if ($DfsrEvent.LevelDisplayName -eq "Error") { "Red" } else { "White" }
        Write-Host "[$($DfsrEvent.TimeCreated)] [$($DfsrEvent.LevelDisplayName)] ID: $($DfsrEvent.Id) - $($DfsrEvent.Message)" -ForegroundColor $EventColor
    }
} else {
    Write-Host "[+] No recent DFSR events or errors detected." -ForegroundColor Green
}
