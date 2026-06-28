# Decommission-InactiveAccounts.ps1
# Description: Disables and moves inactive user (180 days) and computer (90 days) accounts to a stale OU.

Import-Module ActiveDirectory

# Define thresholds
$UserInactivityDays = 180
$ComputerInactivityDays = 90

$UserCutoffDate = (Get-Date).AddDays(-$UserInactivityDays)
$ComputerCutoffDate = (Get-Date).AddDays(-$ComputerInactivityDays)

# Target OU for stale objects (adjust to your environment)
$StaleOU = "OU=StaleObjects,DC=domain,DC=local"
$Exclusions = @("Domain Controllers") # Exclude OUs containing DCs

if (-not (Get-ADOrganizationalUnit -Identity $StaleOU -ErrorAction SilentlyContinue)) {
    Write-Host "[-] Stale OU '$StaleOU' does not exist. Creating it." -ForegroundColor Yellow
    New-ADOrganizationalUnit -Name "StaleObjects" -Path (Get-ADDomain).DistinguishedName -Verbose
}

Write-Host "Scanning for inactive user accounts (no logon in last $UserInactivityDays days)..." -ForegroundColor Cyan
$StaleUsers = Get-ADUser -Filter {Enabled -eq $true -and LastLogonDate -lt $UserCutoffDate -and Name -ne "Administrator" -and Name -ne "Guest"} -Properties LastLogonDate

foreach ($user in $StaleUsers) {
    # Verify the user is not in excluded paths
    $isExcluded = $false
    foreach ($ex in $Exclusions) {
        if ($user.DistinguishedName -like "*$ex*") { $isExcluded = $true }
    }
    if ($isExcluded) { continue }

    Write-Host "Disabling and moving inactive user: $($user.SamAccountName) (Last Logon: $($user.LastLogonDate))" -ForegroundColor Yellow
    Set-ADUser -Identity $user -Enabled $false -Description "Disabled by AD Decommissioning Script - Inactive for $UserInactivityDays days"
    Move-ADObject -Identity $user -TargetPath $StaleOU
}

Write-Host "`nScanning for inactive computer accounts (no logon in last $ComputerInactivityDays days)..." -ForegroundColor Cyan
$StaleComputers = Get-ADComputer -Filter {Enabled -eq $true -and LastLogonDate -lt $ComputerCutoffDate} -Properties LastLogonDate

foreach ($comp in $StaleComputers) {
    $isExcluded = $false
    foreach ($ex in $Exclusions) {
        if ($comp.DistinguishedName -like "*$ex*") { $isExcluded = $true }
    }
    if ($isExcluded) { continue }

    Write-Host "Disabling and moving inactive computer: $($comp.Name) (Last Logon: $($comp.LastLogonDate))" -ForegroundColor Yellow
    Set-ADComputer -Identity $comp -Enabled $false -Description "Disabled by AD Decommissioning Script - Inactive for $ComputerInactivityDays days"
    Move-ADObject -Identity $comp -TargetPath $StaleOU
}

Write-Host "`nDecommissioning process completed." -ForegroundColor Green
