# Set-HardenDefaultAccounts.ps1
# Description: Disables and renames the built-in local Administrator and Guest accounts locally.

Write-Host "Applying hardening requirement: Rename and Disable Default Accounts..." -ForegroundColor Cyan

# 1. Disable and rename built-in local Administrator account
$adminAccount = Get-LocalUser | Where-Object { $_.SID -like "*-500" }
if ($adminAccount) {
    if ($adminAccount.Enabled) {
        Disable-LocalUser -Name $adminAccount.Name
        Write-Host "[+] Local Administrator account ($($adminAccount.Name)) disabled." -ForegroundColor Green
    } else {
        Write-Host "[-] Local Administrator account ($($adminAccount.Name)) is already disabled." -ForegroundColor Yellow
    }
    
    if ($adminAccount.Name -eq "Administrator") {
        Rename-LocalUser -Name "Administrator" -NewName "LocalMgmtAdmin"
        Write-Host "[+] Local Administrator account renamed to LocalMgmtAdmin." -ForegroundColor Green
    } else {
        Write-Host "[-] Local Administrator account is already renamed ($($adminAccount.Name))." -ForegroundColor Yellow
    }
} else {
    Write-Warning "Built-in local Administrator account not found."
}

# 2. Disable and rename built-in local Guest account
$guestAccount = Get-LocalUser | Where-Object { $_.SID -like "*-501" }
if ($guestAccount) {
    if ($guestAccount.Enabled) {
        Disable-LocalUser -Name $guestAccount.Name
        Write-Host "[+] Local Guest account ($($guestAccount.Name)) disabled." -ForegroundColor Green
    } else {
        Write-Host "[-] Local Guest account ($($guestAccount.Name)) is already disabled." -ForegroundColor Yellow
    }
    
    if ($guestAccount.Name -eq "Guest") {
        Rename-LocalUser -Name "Guest" -NewName "LocalMgmtGuest"
        Write-Host "[+] Local Guest account renamed to LocalMgmtGuest." -ForegroundColor Green
    } else {
        Write-Host "[-] Local Guest account is already renamed ($($guestAccount.Name))." -ForegroundColor Yellow
    }
} else {
    Write-Warning "Built-in local Guest account not found."
}
