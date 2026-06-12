# Set-ADSystemStateBackup.ps1
# Installs Windows Server Backup and executes a System State backup.

Write-Host "--- Initializing System State Backup ---" -ForegroundColor Cyan

# 1. Install Windows Server Backup feature if missing
$feature = Get-WindowsFeature -Name Windows-Server-Backup
if ($feature.Installed -eq $false) {
    Write-Host "[+] Installing Windows Server Backup feature..." -ForegroundColor Gray
    Install-WindowsFeature -Name Windows-Server-Backup -IncludeAllSubFeature | Out-Null
    Write-Host "    Feature installed successfully." -ForegroundColor Green
} else {
    Write-Host "[+] Windows Server Backup feature is already installed." -ForegroundColor Green
}

# Import WSB module
Import-Module WindowsServerBackup

# 2. Define Backup Volume Target
$BackupVolumePath = "E:\" # Replace with your designated offline backup storage disk
if (-not (Test-Path $BackupVolumePath)) {
    Write-Error "Backup target volume '$BackupVolumePath' does not exist. Please specify a valid volume."
    exit 1
}

# 3. Create Backup Policy
Write-Host "[+] Configuring System State Backup Policy..." -ForegroundColor Gray
$policy = New-WBPolicy
Add-WBSystemState -Policy $policy | Out-Null

$backupTarget = New-WBBackupTarget -VolumePath $BackupVolumePath
Add-WBBackupTarget -Policy $policy -Target $backupTarget | Out-Null

Write-Host "    Backup Policy created (Target: $BackupVolumePath, Subject: SystemState)." -ForegroundColor Green

# 4. Execute Backup Job
Write-Host "[+] Starting System State Backup. This process can take several minutes..." -ForegroundColor Yellow
$backupJob = Start-WBBackup -Policy $policy -Async

# Monitor backup job status
while ($backupJob.State -eq "Running" -or $backupJob.State -eq "Verifying") {
    Write-Host "    - Backup Progress: $($backupJob.PercentComplete)% complete..." -ForegroundColor Gray
    Start-Sleep -Seconds 10
    # Refresh backup job status
    $backupJob = Get-WBJob
}

# Final output
$finalJob = Get-WBJob -Previous 1
if ($finalJob.JobState -eq "Completed") {
    Write-Host "`nSystem State Backup Completed successfully!" -ForegroundColor Green
} else {
    Write-Error "`nBackup failed with status: $($finalJob.JobState). Error: $($finalJob.ErrorDescription)"
}
