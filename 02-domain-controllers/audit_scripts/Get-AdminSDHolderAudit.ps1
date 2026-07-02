# Get-AdminSDHolderAudit.ps1
# Description: Audits and prints all active permission entries and the inheritance block status on adminSDHolder.

Import-Module ActiveDirectory

Write-Host "--- Auditing adminSDHolder Permissions ---" -ForegroundColor Cyan

$DomainDN = (Get-ADRootDSE).defaultNamingContext
$AdminSDPath = "AD:\CN=adminSDHolder,CN=System,$($DomainDN)"
$Acl = Get-Acl -Path $AdminSDPath

# Check inheritance block status
if ($Acl.AreAccessRulesProtected) {
    Write-Host "[+] Inheritance is BLOCKED (Protected) on the adminSDHolder container (Secure)." -ForegroundColor Green
} else {
    Write-Host "[!] VULNERABLE: Inheritance is ENABLED (Unprotected) on the adminSDHolder container. Permissions may inherit from parent objects." -ForegroundColor Red
}

foreach ($Rule in $Acl.Access) {
    $Identity = $Rule.IdentityReference.Value
    $Rights = $Rule.ActiveDirectoryRights
    $Inheritance = $Rule.InheritanceType
    
    $Color = if ($Rights -match "WriteProperty|WriteDacl|WriteOwner|GenericAll") { "Yellow" } else { "Gray" }
    
    Write-Host "[*] Trustee: $($Identity)" -ForegroundColor White
    Write-Host "    - Rights: $($Rights)" -ForegroundColor $Color
    Write-Host "    - Inheritance: $($Inheritance)" -ForegroundColor Gray
}
