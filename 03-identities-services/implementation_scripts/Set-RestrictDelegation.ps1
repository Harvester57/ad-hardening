# Set-RestrictDelegation.ps1
# Description: Disables unconstrained delegation on computer and user accounts.

Import-Module ActiveDirectory

Write-Host "Applying hardening requirement: Restrict Kerberos Delegation..." -ForegroundColor Cyan

# Find all computer accounts with Unconstrained Delegation
$unconstrainedComputers = Get-ADComputer -Filter {TrustedForDelegation -eq $true}
foreach ($comp in $unconstrainedComputers) {
    Write-Host "[*] Disabling Unconstrained Delegation on Computer: $($comp.SamAccountName)" -ForegroundColor Gray
    Set-ADComputer -Identity $comp -TrustedForDelegation $false
}

# Find all user accounts with Unconstrained Delegation
$unconstrainedUsers = Get-ADUser -Filter {TrustedForDelegation -eq $true}
foreach ($user in $unconstrainedUsers) {
    Write-Host "[*] Disabling Unconstrained Delegation on User: $($user.SamAccountName)" -ForegroundColor Gray
    Set-ADUser -Identity $user -TrustedForDelegation $false
}

Write-Host "Unconstrained delegation has been disabled on all identified accounts." -ForegroundColor Green
