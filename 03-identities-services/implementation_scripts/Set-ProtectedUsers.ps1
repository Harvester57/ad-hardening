# Set-ProtectedUsers.ps1
# Description: Adds privileged accounts to the Protected Users group.

Import-Module ActiveDirectory

Write-Host "Applying hardening requirement: Populate Protected Users Group..." -ForegroundColor Cyan

$GroupName = "Protected Users"
$TargetAdmins = @("admin-t0-user", "admin-t1-user")

foreach ($Admin in $TargetAdmins) {
    $User = Get-ADUser -Filter "SamAccountName -eq '$Admin'"
    
    if ($User) {
        # Check if already a member
        $isMember = Get-ADGroupMember -Identity $GroupName | Where-Object { $_.SamAccountName -eq $Admin }
        
        if (-not $isMember) {
            Add-ADGroupMember -Identity $GroupName -Members $User
            Write-Host "[+] Added $Admin to Protected Users group." -ForegroundColor Green
        } else {
            Write-Host "[-] User $Admin is already a member of Protected Users group." -ForegroundColor Yellow
        }
    } else {
        Write-Warning "User '$Admin' not found in Active Directory."
    }
}
