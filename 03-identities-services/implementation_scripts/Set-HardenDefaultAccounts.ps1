# Set-HardenDefaultAccounts.ps1
# Description: Disables the built-in local Administrator and Guest accounts locally.

Write-Host "Applying hardening requirement: Rename and Disable Default Accounts..." -ForegroundColor Cyan

# 1. Disable built-in local Administrator account
$adminAccount = Get-LocalUser -SID "S-1-5-32-544" | Where-Object { $_.SID -like "*-500" }
if ($adminAccount) {
    if ($adminAccount.Enabled) {
        Disable-LocalUser -Name $adminAccount.Name
        Write-Host "[+] Local Administrator account ($($adminAccount.Name)) disabled." -ForegroundColor Green
    } else {
        Write-Host "[-] Local Administrator account ($($adminAccount.Name)) is already disabled." -ForegroundColor Yellow
    }
} else {
    Write-Warning "Built-in local Administrator account not found."
}

# 2. Disable built-in local Guest account
$guestAccount = Get-LocalUser -SID "S-1-5-32-544" | Where-Object { $_.SID -like "*-501" }
# Fallback to standard check if SID group matches local guest
if (-not $guestAccount) {
    $guestAccount = Get-LocalUser | Where-Object { $_.SID -like "*-501" }
}

if ($guestAccount) {
    if ($guestAccount.Enabled) {
        Disable-LocalUser -Name $guestAccount.Name
        Write-Host "[+] Local Guest account ($($guestAccount.Name)) disabled." -ForegroundColor Green
    } else {
        Write-Host "[-] Local Guest account ($($guestAccount.Name)) is already disabled." -ForegroundColor Yellow
    }
} else {
    Write-Warning "Built-in local Guest account not found."
}
