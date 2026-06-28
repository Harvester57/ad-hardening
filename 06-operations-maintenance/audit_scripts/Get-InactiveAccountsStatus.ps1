# Get-InactiveAccountsStatus.ps1
# Audits the directory for enabled but inactive user (180 days) and computer (90 days) accounts.

Import-Module ActiveDirectory

$UserInactivityDays = 180
$ComputerInactivityDays = 90

$UserCutoffDate = (Get-Date).AddDays(-$UserInactivityDays)
$ComputerCutoffDate = (Get-Date).AddDays(-$ComputerInactivityDays)

$StaleUsers = Get-ADUser -Filter {Enabled -eq $true -and LastLogonDate -lt $UserCutoffDate -and Name -ne "Administrator" -and Name -ne "Guest"} -Properties LastLogonDate
$StaleComputers = Get-ADComputer -Filter {Enabled -eq $true -and LastLogonDate -lt $ComputerCutoffDate} -Properties LastLogonDate

$Exclusions = @("Domain Controllers")

$nonCompliantCount = 0

foreach ($user in $StaleUsers) {
    $isExcluded = $false
    foreach ($ex in $Exclusions) {
        if ($user.DistinguishedName -like "*$ex*") { $isExcluded = $true }
    }
    if ($isExcluded) { continue }

    Write-Host "[!] NON-COMPLIANT: User account '$($user.SamAccountName)' is enabled but inactive since $($user.LastLogonDate)" -ForegroundColor Red
    $nonCompliantCount++
}

foreach ($comp in $StaleComputers) {
    $isExcluded = $false
    foreach ($ex in $Exclusions) {
        if ($comp.DistinguishedName -like "*$ex*") { $isExcluded = $true }
    }
    if ($isExcluded) { continue }

    Write-Host "[!] NON-COMPLIANT: Computer account '$($comp.Name)' is enabled but inactive since $($comp.LastLogonDate)" -ForegroundColor Red
    $nonCompliantCount++
}

if ($nonCompliantCount -eq 0) {
    Write-Host "[+] COMPLIANT: No stale enabled user or computer accounts detected." -ForegroundColor Green
    exit 0
} else {
    Write-Host "[!] NON-COMPLIANT: Detected $nonCompliantCount stale enabled accounts that need to be decommissioned." -ForegroundColor Red
    exit 1
}
