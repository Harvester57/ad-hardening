# Test-PawLocalAdministrators.ps1
# Description: Audits local Administrators group memberships to ensure only authorized Tier 0 accounts are present.

Write-Host "--- Auditing PAW Local Administrators Group ---" -ForegroundColor Cyan

# Define the authorized domain/local patterns
$AuthorizedMembers = @("Administrator", "Tier0-Admins")

$LocalAdmins = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue

if ($LocalAdmins) {
    Write-Host "[*] Current members of local Administrators group:" -ForegroundColor Yellow
    foreach ($Member in $LocalAdmins) {
        $Match = $false
        foreach ($Auth in $AuthorizedMembers) {
            if ($Member.Name -eq $Auth -or $Member.Name -like "*\$Auth" -or $Member.Name -eq "$env:COMPUTERNAME\$Auth") {
                $Match = $true
                break
            }
        }
        
        if (-not $Match) {
            Write-Host "    - VULNERABLE: Unauthorized account '$($Member.Name)' (Source: $($Member.PrincipalSource)) has administrative access." -ForegroundColor Red
        } else {
            Write-Host "    - Member: $($Member.Name) | Source: $($Member.PrincipalSource) | Class: $($Member.ObjectClass) (Authorized)" -ForegroundColor Green
        }
    }
} else {
    Write-Error "Failed to retrieve local Administrators group members."
}
