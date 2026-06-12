# Cleanup-AdminCountOrphans.ps1
# Description: Resets adminCount and re-enables inheritance on user accounts that are no longer in protected groups.

Import-Module ActiveDirectory

Write-Host "Applying hardening requirement: Clean Up adminCount Attribute Orphans..." -ForegroundColor Cyan

# Define the list of built-in protected AD groups (sAMAccountNames)
$ProtectedGroups = @(
    "Administrators",
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins",
    "Account Operators",
    "Backup Operators",
    "Print Operators",
    "Server Operators",
    "Cert Publishers",
    "Group Policy Creator Owners"
)

# Fetch all user objects with adminCount set to 1
Write-Host "Scanning domain for accounts with adminCount = 1..." -ForegroundColor White
$Orphans = Get-ADUser -Filter "adminCount -eq 1" -Properties MemberOf, adminCount

$CleanedCount = 0

foreach ($User in $Orphans) {
    $IsStillProtected = $false
    
    # Check if the user is currently in any of the protected groups
    foreach ($Group in $ProtectedGroups) {
        $GroupObj = Get-ADGroup -Filter "Name -eq '$Group'" -ErrorAction SilentlyContinue
        if ($null -ne $GroupObj) {
            # Check membership
            $IsMember = Get-ADGroupMember -Identity $GroupObj -Recursive | Where-Object { $_.distinguishedName -eq $User.distinguishedName }
            if ($null -ne $IsMember) {
                $IsStillProtected = $true
                break
            }
        }
    }
    
    # If the user is no longer in a protected group, perform cleanup
    if (-not $IsStillProtected) {
        Write-Host "[-] Found orphan account: $($User.SamAccountName)" -ForegroundColor Yellow
        
        # 1. Clear the adminCount attribute
        Set-ADUser -Identity $User.distinguishedName -Clear "adminCount" -ErrorAction Stop
        
        # 2. Re-enable ACL inheritance on the object
        $UserDN = $User.distinguishedName
        $AclPath = "AD:\$($UserDN)"
        $Acl = Get-Acl -Path $AclPath
        
        if ($Acl.AreAccessRulesProtected) {
            # Disable protection, copying existing rules as inherited
            $Acl.SetAccessRuleProtection($false, $true)
            Set-Acl -Path $AclPath -AclObject $Acl -ErrorAction Stop
            Write-Host "    - Reset adminCount and enabled security inheritance." -ForegroundColor Green
        } else {
            Write-Host "    - Reset adminCount (security inheritance was already enabled)." -ForegroundColor Green
        }
        
        $CleanedCount++
    }
}

Write-Host "[+] Cleanup complete. Total orphan accounts remediated: $($CleanedCount)." -ForegroundColor Green
