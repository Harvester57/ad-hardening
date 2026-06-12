# Get-AdminSDHolderAudit.ps1
# Description: Audits and prints all active permission entries on adminSDHolder.

Import-Module ActiveDirectory

Write-Host "--- Auditing adminSDHolder Permissions ---" -ForegroundColor Cyan

$DomainDN = (Get-ADRootDSE).defaultNamingContext
$AdminSDPath = "AD:\CN=adminSDHolder,CN=System,$($DomainDN)"
$Acl = Get-Acl -Path $AdminSDPath

foreach ($Rule in $Acl.Access) {
    $Identity = $Rule.IdentityReference.Value
    $Rights = $Rule.ActiveDirectoryRights
    $Inheritance = $Rule.InheritanceType
    
    $Color = if ($Rights -match "WriteProperty|WriteDacl|WriteOwner|GenericAll") { "Yellow" } else { "Gray" }
    
    Write-Host "[*] Trustee: $($Identity)" -ForegroundColor White
    Write-Host "    - Rights: $($Rights)" -ForegroundColor $Color
    Write-Host "    - Inheritance: $($Inheritance)" -ForegroundColor Gray
}
