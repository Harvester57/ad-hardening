# Clean-PawLocalAdministrators.ps1
# Description: Removes unauthorized accounts from the local Administrators group on PAWs.

Write-Host "--- Restricting Local Administrators Group on PAW ---" -ForegroundColor Cyan

# Define the list of authorized members
# Built-in Administrator and Tier 0 admin groups
$AuthorizedMembers = @("Administrator", "Tier0-Admins")

$LocalAdmins = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue

if ($LocalAdmins) {
    foreach ($Member in $LocalAdmins) {
        $Match = $false
        foreach ($Auth in $AuthorizedMembers) {
            if ($Member.Name -eq $Auth -or $Member.Name -like "*\$Auth" -or $Member.Name -eq "$env:COMPUTERNAME\$Auth") {
                $Match = $true
                break
            }
        }
        
        if (-not $Match) {
            Write-Host "[-] Removing unauthorized member from Administrators: $($Member.Name) (Source: $($Member.PrincipalSource))" -ForegroundColor Yellow
            try {
                Remove-LocalGroupMember -Group "Administrators" -Member $Member.Name -ErrorAction Stop
                Write-Host "    Successfully removed: $($Member.Name)" -ForegroundColor Green
            } catch {
                Write-Error "    Failed to remove: $($Member.Name). Error: $($_.Exception.Message)"
            }
        } else {
            Write-Host "[+] Member authorized: $($Member.Name)" -ForegroundColor Green
        }
    }
} else {
    Write-Error "Could not retrieve members of local Administrators group."
}
