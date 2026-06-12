# Get-AdminCountOrphansAudit.ps1
# Description: Scans the domain and prints all orphan adminCount accounts.

Import-Module ActiveDirectory

Write-Host "--- Auditing adminCount Orphans ---" -ForegroundColor Cyan

$ProtectedGroups = @("Administrators","Domain Admins","Enterprise Admins","Schema Admins","Account Operators","Backup Operators","Print Operators","Server Operators")
$Users = Get-ADUser -Filter "adminCount -eq 1"

$OrphanCount = 0

foreach ($U in $Users) {
    $Member = $false
    foreach ($Grp in $ProtectedGroups) {
        $GrpObj = Get-ADGroup -Filter "Name -eq '$Grp'"
        if ($GrpObj) {
            $Check = Get-ADGroupMember -Identity $GrpObj -Recursive | Where-Object { $_.distinguishedName -eq $U.distinguishedName }
            if ($Check) {
                $Member = $true
                break
            }
        }
    }
    
    if (-not $Member) {
        Write-Host "[!] Orphan: $($U.SamAccountName) has adminCount=1 but is not in protected groups." -ForegroundColor Yellow
        $OrphanCount++
    }
}

Write-Host "[*] Total adminCount orphans detected: $($OrphanCount)." -ForegroundColor White
