# Audit-SchemaAdminsGroup.ps1
# Description: Audits the Schema Admins group membership.

Import-Module ActiveDirectory

Write-Host "--- Auditing Schema Admins Group Membership ---" -ForegroundColor Cyan

try {
    $Group = Get-ADGroup -Identity "Schema Admins" -Properties Members -ErrorAction Stop
    $MembersCount = $Group.Members.Count
    
    if ($MembersCount -gt 0) {
        Write-Host "`nVULNERABLE: Schema Admins group is NOT empty. Found $MembersCount member(s):" -ForegroundColor Red
        foreach ($memberDN in $Group.Members) {
            $memberObj = Get-ADObject -Identity $memberDN -ErrorAction SilentlyContinue
            Write-Host "    - Member: $($memberObj.Name) | DN: $memberDN" -ForegroundColor White
        }
    } else {
        Write-Host "`nStatus: Compliant. Schema Admins group is empty." -ForegroundColor Green
    }
} catch {
    Write-Host "VULNERABLE: Could not query Schema Admins group. Error: $($_.Exception.Message)" -ForegroundColor Red
}
