# Get-DefaultAccountsStatus.ps1
# Description: Audits the enabled status of the built-in local Administrator and Guest accounts.

Write-Host "--- Auditing Default Accounts Status ---" -ForegroundColor Cyan

$adminAccount = Get-LocalUser | Where-Object { $_.SID -like "*-500" }
$guestAccount = Get-LocalUser | Where-Object { $_.SID -like "*-501" }

if ($adminAccount) {
    $adminColor = if ($adminAccount.Enabled) { "Red" } else { "Green" }
    Write-Host "    - Local Administrator ($($adminAccount.Name)): Enabled = $($adminAccount.Enabled)" -ForegroundColor $adminColor
}

if ($guestAccount) {
    $guestColor = if ($guestAccount.Enabled) { "Red" } else { "Green" }
    Write-Host "    - Local Guest ($($guestAccount.Name)): Enabled = $($guestAccount.Enabled)" -ForegroundColor $guestColor
}
