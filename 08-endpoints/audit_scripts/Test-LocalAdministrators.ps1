# Test-LocalAdministrators.ps1
# Audits membership of the local Administrators group to find unauthorized domain accounts.

Write-Host "--- Auditing Local Administrators Group ---" -ForegroundColor Cyan

$LocalAdmins = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue

if ($LocalAdmins) {
    Write-Host "[*] Current members of local Administrators group:" -ForegroundColor Yellow
    foreach ($Member in $LocalAdmins) {
        # Flag any domain user accounts that might have been added to administrators group
        $StatusColor = "Green"
        if ($Member.PrincipalSource -eq "ActiveDirectory" -and $Member.Name -notmatch "Workstation-Support-Admins") {
            $StatusColor = "Red"
            Write-Host "    - VULNERABLE: Domain Account '$($Member.Name)' has local admin rights." -ForegroundColor $StatusColor
        } else {
            Write-Host "    - Member: $($Member.Name) | Source: $($Member.PrincipalSource) | Class: $($Member.ObjectClass)" -ForegroundColor $StatusColor
        }
    }
} else {
    Write-Error "Failed to retrieve local Administrators group members."
}
