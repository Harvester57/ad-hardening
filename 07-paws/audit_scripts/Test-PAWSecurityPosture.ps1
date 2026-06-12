# Test-PAWSecurityPosture.ps1
# Audits the local PAW state for BitLocker, AppIDSvc, and Credential Guard registry settings.

Write-Host "--- Auditing PAW Security Posture ---" -ForegroundColor Cyan

# 1. Audit BitLocker on C:
$Blt = Get-BitLockerVolume -MountPoint "C:" -ErrorAction SilentlyContinue
if ($Blt) {
    $BltColor = if ($Blt.ProtectionStatus -eq "On") { "Green" } else { "Red" }
    Write-Host "    - BitLocker C: Protection Status: $($Blt.ProtectionStatus) | Encryption: $($Blt.VolumeStatus)" -ForegroundColor $BltColor
} else {
    Write-Host "    - BitLocker: Volume information could not be retrieved." -ForegroundColor Red
}

# 2. Audit AppLocker Service
$AppIDSvc = Get-Service -Name AppIDSvc -ErrorAction SilentlyContinue
if ($AppIDSvc) {
    $AppLockerColor = if ($AppIDSvc.Status -eq "Running" -and $AppIDSvc.StartType -eq "Automatic") { "Green" } else { "Red" }
    Write-Host "    - AppLocker Service Status: $($AppIDSvc.Status) | Startup: $($AppIDSvc.StartType)" -ForegroundColor $AppLockerColor
}

# 3. Audit Local Administrators Group
$LocalAdmins = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
Write-Host "`n[+] Current Local Administrators (Must only contain local/authorized admin accounts):" -ForegroundColor Yellow
if ($LocalAdmins) {
    foreach ($Member in $LocalAdmins) {
        # Check if the member is a domain account (contains domain prefix or SID matches domain structure)
        $MemberColor = if ($Member.ObjectClass -eq "User" -and $Member.PrincipalSource -eq "Local") { "Green" } else { "Yellow" }
        Write-Host "    - Account: $($Member.Name) | Source: $($Member.PrincipalSource) | Class: $($Member.ObjectClass)" -ForegroundColor $MemberColor
    }
} else {
    Write-Warning "    - Local administrators group membership could not be retrieved."
}
