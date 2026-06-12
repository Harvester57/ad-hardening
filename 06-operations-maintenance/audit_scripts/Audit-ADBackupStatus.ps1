# Audit-ADBackupStatus.ps1
# Audits the status of local system state backups.

Import-Module WindowsServerBackup -ErrorAction SilentlyContinue

Write-Host "--- Auditing System State Backup Status ---" -ForegroundColor Cyan

# Check if Windows Server Backup feature is installed
$feature = Get-WindowsFeature -Name Windows-Server-Backup -ErrorAction SilentlyContinue
if ($feature -and $feature.Installed -eq $false) {
    Write-Warning "Windows Server Backup feature is NOT installed on this machine."
    exit 1
}

# Retrieve history of local backups
try {
    $backups = Get-WBBackupSet -ErrorAction Stop
    Write-Host "`n[+] Found $($backups.Count) recorded backup sets." -ForegroundColor Yellow
    
    # Sort and output the most recent backups
    $sortedBackups = $backups | Sort-Object -Property BackupTime -Descending
    foreach ($bk in $sortedBackups | Select-Object -First 5) {
        $containsSystemState = $bk.CatalogFlags -match "SystemState"
        $statusColor = if ($containsSystemState) { "Green" } else { "Yellow" }
        Write-Host "    - Backup Time: $($bk.BackupTime) | Location: $($bk.VolumePath) | Contains SystemState: $containsSystemState" -ForegroundColor $statusColor
    }
} catch {
    Write-Host "[-] No backup records found on the system. System state backups may not be configured." -ForegroundColor Red
}
