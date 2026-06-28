# Get-OfflineWsusSyncStatus.ps1
# Description: Checks the synchronization history of the local WSUS server.

Import-Module UpdateServices -ErrorAction SilentlyContinue

Write-Host "--- Auditing WSUS Offline Synchronization Status ---" -ForegroundColor Cyan

try {
    # Connect to the local WSUS server
    $wsus = [Microsoft.UpdateServices.Administration.AdminProxy]::GetUpdateServer()
    $history = $wsus.GetSubscription().GetSynchronizationHistory()
    
    if ($history.Count -gt 0) {
        $lastSync = $history[0]
        Write-Host "[+] Last WSUS Sync Time: $($lastSync.EndTime)" -ForegroundColor Green
        Write-Host "[+] Last WSUS Sync Result: $($lastSync.Result)" -ForegroundColor Green
        if ($lastSync.Result -eq "Succeeded") {
            exit 0
        } else {
            Write-Warning "Last WSUS Sync did not succeed."
            exit 1
        }
    } else {
        Write-Host "[-] No WSUS synchronization history found." -ForegroundColor Red
        exit 1
    }
} catch {
    Write-Host "[-] Failed to retrieve WSUS synchronization history. Ensure the WSUS role is installed and services are running." -ForegroundColor Red
    exit 1
}
