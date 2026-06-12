# Audit-ADAdminGroups.ps1
# Queries memberships of privileged Tier 0 AD groups recursively.

Import-Module ActiveDirectory

$Tier0Groups = @(
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins",
    "Administrators",
    "Account Operators",
    "Server Operators",
    "Backup Operators"
)

Write-Host "--- Auditing Privileged AD Groups ---" -ForegroundColor Cyan

# Define the list of explicitly authorized accounts (e.g. emergency break-glass account)
$AuthorizedUsers = @("Administrator", "a0-breakglass")

foreach ($GroupName in $Tier0Groups) {
    try {
        $Group = Get-ADGroup -Identity $GroupName -ErrorAction Stop
        $Members = Get-ADGroupMember -Identity $GroupName -Recursive
        
        Write-Host "`n[+] Group: $($Group.Name)" -ForegroundColor Yellow
        if ($Members.Count -eq 0) {
            Write-Host "    No members found." -ForegroundColor Gray
        } else {
            foreach ($Member in $Members) {
                # Highlight unauthorized accounts in red
                if ($AuthorizedUsers -notcontains $Member.SamAccountName -and $Member.SamAccountName -notlike "a0-*") {
                    Write-Host "    - VULNERABLE: Unauthorized user '$($Member.SamAccountName)' in admin group!" -ForegroundColor Red
                } else {
                    Write-Host "    - Member: $($Member.SamAccountName) | Class: $($Member.objectClass)" -ForegroundColor Green
                }
            }
        }
    } catch {
        Write-Warning "Could not query group '$GroupName'. Ensure appropriate permissions."
    }
}
