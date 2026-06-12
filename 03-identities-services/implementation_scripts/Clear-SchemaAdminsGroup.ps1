# Clear-SchemaAdminsGroup.ps1
# Description: Removes all members from the Schema Admins group.

Import-Module ActiveDirectory

Write-Host "Applying hardening requirement: Clear Schema Admins group membership..." -ForegroundColor Cyan

try {
    $Group = Get-ADGroup -Identity "Schema Admins" -Properties Members -ErrorAction Stop
    
    if ($Group.Members.Count -gt 0) {
        Write-Host "[+] Found $($Group.Members.Count) members in Schema Admins group." -ForegroundColor Yellow
        foreach ($memberDN in $Group.Members) {
            $memberObj = Get-ADObject -Identity $memberDN
            Remove-ADGroupMember -Identity "Schema Admins" -Members $memberDN -Confirm:$false -ErrorAction Stop
            Write-Host "    Removed member: $($memberObj.Name)" -ForegroundColor Green
        }
        Write-Host "[+] Schema Admins group cleared successfully." -ForegroundColor Green
    } else {
        Write-Host "[+] Schema Admins group is already empty." -ForegroundColor Green
    }
} catch {
    Write-Error "Failed to clear Schema Admins group. Error: $($_.Exception.Message)"
}
