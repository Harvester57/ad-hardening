# Configure-PrivilegedSmartCard.ps1
# Description: Enforces the 'Smart card is required for interactive logon' flag on a specified user group.
# Target Engine: Windows PowerShell 5.1

Write-Host "Applying smart card logon requirement to administrative accounts..." -ForegroundColor Cyan

if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Error "ActiveDirectory PowerShell module is not available. Please run this script on a system with AD DS RSAT tools."
    exit 1
}

Import-Module ActiveDirectory

$GroupName = "Tier0_Administrators"
$Group = Get-ADGroup -Filter "Name -eq '$GroupName'"
if (-not $Group) {
    Write-Host "Group $GroupName not found. Defaulting to Domain Admins..." -ForegroundColor Yellow
    $GroupName = "Domain Admins"
}

$Members = Get-ADGroupMember -Identity $GroupName -Recursive | Where-Object { $_.objectClass -eq "user" }

if (-not $Members) {
    Write-Host "No users found in group $GroupName." -ForegroundColor Yellow
    exit 0
}

foreach ($Member in $Members) {
    $User = Get-ADUser -Identity $Member.distinguishedName -Properties SmartcardRequired
    if (-not $User.SmartcardRequired) {
        Write-Host "Enforcing smart card requirement for user: $($User.SamAccountName)" -ForegroundColor Cyan
        Set-ADUser -Identity $User.distinguishedName -SmartcardRequired $true
    } else {
        Write-Host "User $($User.SamAccountName) already requires smart card." -ForegroundColor Green
    }
}

Write-Host "Smart card requirement configuration complete." -ForegroundColor Green
