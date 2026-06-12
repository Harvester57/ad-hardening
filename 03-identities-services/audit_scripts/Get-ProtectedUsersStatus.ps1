# Get-ProtectedUsersStatus.ps1
# Description: Lists all members of the Protected Users security group.

Import-Module ActiveDirectory

Write-Host "--- Auditing Protected Users Group Members ---" -ForegroundColor Cyan

$GroupName = "Protected Users"
$Members = Get-ADGroupMember -Identity $GroupName -ErrorAction SilentlyContinue

if ($Members) {
    Write-Host "[+] Members of the Protected Users group:" -ForegroundColor Green
    foreach ($Member in $Members) {
        Write-Host "    - $($Member.SamAccountName) (Type: $($Member.objectClass))" -ForegroundColor White
    }
} else {
    Write-Host "[!] VULNERABLE: No members found in the Protected Users group. Administrative accounts may be unprotected." -ForegroundColor Red
}
