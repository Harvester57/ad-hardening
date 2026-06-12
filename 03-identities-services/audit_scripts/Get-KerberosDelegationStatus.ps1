# Get-KerberosDelegationStatus.ps1
# Description: Audits accounts with unconstrained delegation in the Active Directory domain.

Import-Module ActiveDirectory

Write-Host "--- Auditing Kerberos Delegation Settings ---" -ForegroundColor Cyan

$unconstrainedComputers = Get-ADComputer -Filter {TrustedForDelegation -eq $true}
$unconstrainedUsers = Get-ADUser -Filter {TrustedForDelegation -eq $true}

$totalUnconstrained = $unconstrainedComputers.Count + $unconstrainedUsers.Count

if ($totalUnconstrained -eq 0) {
    Write-Host "[+] Secure: No accounts found with Unconstrained Delegation." -ForegroundColor Green
} else {
    foreach ($comp in $unconstrainedComputers) {
        Write-Host "[!] VULNERABLE: Computer with Unconstrained Delegation: $($comp.SamAccountName)" -ForegroundColor Red
    }
    foreach ($user in $unconstrainedUsers) {
        Write-Host "[!] VULNERABLE: User with Unconstrained Delegation: $($user.SamAccountName)" -ForegroundColor Red
    }
}
