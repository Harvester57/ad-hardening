# Hardening Requirement: Clean Up adminCount Attribute Orphans

## Target Scope
* **Applicable Systems**: Domain Controllers, Identity Management
* **Operating Systems**: Windows Server 2016, Windows Server 2019, Windows Server 2022

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**: Active Directory User Object attributes (`adminCount` and Security Descriptor inheritance flag)

---

## Rationale
In Active Directory, when an account is added to a protected group (such as `Domain Admins`, `Schema Admins`, or `Account Operators`), a background system process called SDPROP automatically sets the account's `adminCount` attribute to `1` and disables security descriptor inheritance. This is done to ensure the account only inherits permissions defined by the secure `adminSDHolder` template rather than any insecure permissions on the parent Organizational Unit (OU).

However, if that user is later removed from the protected group:
1. **adminCount Remains Active**: Active Directory does not automatically reset the `adminCount` attribute to `0` or empty, nor does it re-enable security descriptor inheritance on the user object.
2. **Leaves Account Insecurely Unmanaged**: The user object remains orphaned, with inheritance permanently disabled. This blocks future legitimate GPO-based permission updates and can allow persistent, hidden permissions (backdoors) on the object to remain unmitigated.
3. **Breaks Management Consistency**: Security administrators auditing protected accounts will see false positives, as accounts appear to have administrative attributes when they do not have administrative group memberships.

Auditing and resetting these orphan accounts restores proper security inheritance and cleans up directory metadata.

---

## Legacy Impact & Compatibility
* **Parent OU Access Control**: Re-enabling security inheritance on a user object will immediately apply the Access Control Lists (ACLs) of its parent Organizational Unit. Before re-enabling inheritance, ensure that the target user's parent OU is properly secured and does not grant excessive delegation permissions to non-Tier 0 accounts.
* **Service Interruption**: No service interruption is expected, as this is an attribute cleanup task.

---

## Implementation Steps

### Option A: Active Directory Administrative Center (ADAC) Manual Modification

1. Open **Active Directory Administrative Center** (`dsac.exe`) on a Domain Controller.
2. Navigate to your domain and locate the target orphan user account.
3. Right-click the user account and select **Properties**.
4. Click **Attribute Editor** (ensure Advanced features are active).
5. Locate the **adminCount** attribute and click **Clear** or set the value to `<not set>`.
6. Select the **Security** tab, click **Advanced**, and click **Enable Inheritance**.
7. Click **OK** to save and commit changes.

---

### Option B: PowerShell Configuration (Remediation / Non-GPO)

Run the following script to automatically identify all user accounts with `adminCount=1` that are no longer members of any protected AD group, reset the attribute, and re-enable security inheritance.

```powershell
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
```

*To audit and list orphan accounts without making changes:*
```powershell
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
```

---

## Sources & Compliance References
* **ANSSI Remediation of Active Directory Tier 0 Guide**: Section 6.b (Page 32)
* **ANSSI AD Hardening Guide**: Section 3.2.2 (adminSDHolder Context)
* **Microsoft Security Guidance**: Active Directory Orphaned adminCount Cleanup Procedures
