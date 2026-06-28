# [REQ-OPS-008] Configure Daily System State Backups

## Target Scope
* **Applicable Systems**: Domain Controllers
* **Operating Systems**: Windows Server 2016, Windows Server 2019, Windows Server 2022

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**: Windows Server Backup feature and local backup policies

---

## Rationale
Disaster Recovery is a core pillar of Active Directory security. If Domain Controllers are corrupted or compromised, administrators must recover from trusted, clean states.

The System State contains the Active Directory database (ntds.dit), the SYSVOL share, registry settings, certificates, and DNS records. 

To ensure resilience:
1. **Daily Frequency**: Create System State Backups daily on at least two Domain Controllers to minimize data loss.
2. **Storage Isolation (Offline/Immutable)**: Backups must be stored on separate physical or virtual storage. In high-security systems, enforce write-once-read-many (WORM) storage or store backups in an offline, physically secured media rotation to prevent modifications by compromised accounts.
3. **Regular Validation**: Run recovery exercises quarterly in an isolated network sandbox to verify that restored DCs are functional and free of replication loops.

---

## Legacy Impact & Compatibility
* **Performance Impact**: Creating a system state backup utilizes significant disk I/O and CPU resources. It should be scheduled during off-peak hours to avoid affecting authentication response times.
* **Storage Requirements**: System State backups consume considerable storage space (typically 10-20 GB or more depending on database size). Ensure target volumes have adequate capacity and are configured to automatically prune older backups.
* **Access Control**: Backups contain the Active Directory database (including credentials hashes). The backup destination volume must be restricted via NTFS permissions to only Domain Admins and the SYSTEM account.

---

## Implementation Steps

### Option A: Graphical User Interface (GUI) Configuration

1. Log in to the Domain Controller and open **Server Manager**.
2. Click **Manage** -> **Add Roles and Features**.
3. Advance to the **Features** step, check **Windows Server Backup**, and complete the installation.
4. Open the administrative tool **Windows Server Backup** (wbadmin.msc).
5. In the Actions pane, click **Backup Schedule...**.
6. In the Backup Schedule Wizard, click **Next** on the Getting Started page.
7. Select **Custom** configuration and click **Next**.
8. Click **Add Items**, check **System State**, and click **OK**.
9. Specify the time and frequency (once a day, during off-peak hours) and click **Next**.
10. Choose the destination type (dedicated backup disk, volume, or shared network folder) and complete the wizard.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script block to install the Windows Server Backup feature, configure a System State backup policy, and execute an immediate System State backup to a designated disk volume.

[Download Script: Set-ADSystemStateBackup.ps1](implementation_scripts/Set-ADSystemStateBackup.ps1)

```powershell
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
```

*To verify active backup configurations:*

[Download Script: Audit-ADBackupStatus.ps1](audit_scripts/Audit-ADBackupStatus.ps1)

```powershell
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
```

---

## Sources & Compliance References
* **ANSSI AD Hardening Guide**: Recommendation R54 (Domain Controller backup and disaster recovery)
* **Microsoft Security Guidance**: Active Directory Backup and Restore Best Practices
