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

# Audit Backup Target Access Control List
$policy = Get-WBPolicy -ErrorAction SilentlyContinue
if ($policy) {
    $targets = Get-WBBackupTarget -Policy $policy -ErrorAction SilentlyContinue
    foreach ($target in $targets) {
        $path = $null
        if ($target.VolumePath) {
            $path = $target.VolumePath
        } elseif ($target.NetworkPath) {
            $path = $target.NetworkPath
        }
        
        if ($path) {
            Write-Host "`n[*] Auditing backup target permissions: $path" -ForegroundColor Gray
            if (Test-Path $path) {
                $acl = Get-Acl -Path $path -ErrorAction SilentlyContinue
                if ($acl) {
                    $unauthorized = $false
                    foreach ($access in $acl.Access) {
                        $identity = $access.IdentityReference.Value
                        $rights = $access.FileSystemRights
                        $type = $access.AccessControlType
                        
                        if ($type -eq "Allow") {
                            if ($identity -notmatch "SYSTEM|Administrators|Domain Admins|Enterprise Admins|Creator Owner|NT AUTHORITY\\SYSTEM|BUILTIN\\Administrators") {
                                if ($rights -match "Read|Write|Modify|FullControl") {
                                    Write-Host "    [!] WARNING: Unauthorized identity '$identity' has '$rights' access to backup target." -ForegroundColor Red
                                    $unauthorized = $true
                                }
                            }
                        }
                    }
                    if (-not $unauthorized) {
                        Write-Host "    [+] Target directory ACL is securely restricted." -ForegroundColor Green
                    }
                } else {
                    Write-Warning "    Could not retrieve ACL for backup target."
                }
            } else {
                Write-Host "    [-] Backup target path is currently offline or unreachable." -ForegroundColor Yellow
            }
        }
    }
}
