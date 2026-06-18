# Test-PrivilegedSmartCard.ps1
# Description: Audits if all members of the specified administrative group require smart card for logon.
# Target Engine: Windows PowerShell 5.1

Write-Host "--- Auditing Privileged User Smart Card Requirements ---" -ForegroundColor Cyan

if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Warning "ActiveDirectory PowerShell module is not available. Please install RSAT AD DS tools."
    exit 0
}

Import-Module ActiveDirectory

$GroupName = "Tier0_Administrators"
$Group = Get-ADGroup -Filter "Name -eq '$GroupName'"
if (-not $Group) {
    Write-Host "Group $GroupName not found. Defaulting audit to Domain Admins..." -ForegroundColor Yellow
    $GroupName = "Domain Admins"
}

$Vulnerable = $false
$Members = Get-ADGroupMember -Identity $GroupName -Recursive | Where-Object { $_.objectClass -eq "user" }

if (-not $Members) {
    Write-Host "No users found in group $GroupName to audit." -ForegroundColor Yellow
} else {
    foreach ($Member in $Members) {
        $User = Get-ADUser -Identity $Member.distinguishedName -Properties SmartcardRequired
        if (-not $User.SmartcardRequired) {
            Write-Host "    - User: $($User.SamAccountName) | Actual: Password Allowed (Expected: Smart Card Required)" -ForegroundColor Red
            $Vulnerable = $true
        } else {
            Write-Host "    - User: $($User.SamAccountName) | Actual: Smart Card Required (Expected: Smart Card Required)" -ForegroundColor Green
        }
    }
}

if ($Vulnerable) {
    Write-Host "Audit Result: VULNERABLE" -ForegroundColor Red
    exit 1
} else {
    Write-Host "Audit Result: SECURE" -ForegroundColor Green
    exit 0
}
