# [REQ-DC-016] Harden adminSDHolder Permissions

## Target Scope
* **Applicable Systems**: Domain Controllers
* **Operating Systems**: Windows Server 2016, Windows Server 2019, Windows Server 2022

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**: Active Directory Object Path: `CN=adminSDHolder,CN=System,DC=[Domain]`

---

## Rationale
In Active Directory, the `adminSDHolder` object acts as a security template for administrative accounts and groups (known as protected objects). Every hour, a background system thread (the `AdminSDHolder` task, also referred to as the `ProtectAdminGroups` task) running on the Domain Controller holding the PDC Emulator role compares the Access Control Lists (ACLs) of all protected objects against the ACL of the `adminSDHolder` object. If they differ, the ACL on the protected object is overwritten by the ACL on `adminSDHolder`, and security inheritance is disabled.

A common misconception is that the Security Descriptor Propagator (`SDProp`) thread enforces this protection. In reality, `SDProp` is a separate background thread on all Domain Controllers whose sole job is to propagate inheritable Access Control Entries (ACEs) when an object is moved or a parent ACL is modified. The actual enforcement of the `adminSDHolder` template is performed exclusively by the `AdminSDHolder` background task.

If an attacker gains temporary write permissions on the `adminSDHolder` object, they can inject a backdoor Access Control Entry (ACE) granting their account write permissions. Within an hour, the `AdminSDHolder` background task will apply this backdoor ACE to all protected groups (e.g., Domain Admins, Schema Admins, Enterprise Admins). Even if the administrator cleans up permissions on a Domain Admin account directly, the `AdminSDHolder` task will restore the backdoor ACE on its next run.

### The Importance of Container Inheritance Protection (DACL_Protected)
By default, the `adminSDHolder` container itself (`CN=adminSDHolder,CN=System,DC=[Domain]`) has its DACL protected (inheritance blocked). This prevents permissions delegated on the parent `CN=System` container or the Domain Root from inheriting down to the `adminSDHolder` object. If inheritance is accidentally enabled on `CN=adminSDHolder`, any account with write permissions delegated on parent containers would implicitly gain control over `adminSDHolder`, resulting in full domain compromise when those permissions are propagated to all administrative accounts.

### Protection of Non-User Objects
The `AdminSDHolder` task is not restricted to user objects and groups. It will also protect computer objects, Managed Service Accounts (MSAs), and Group Managed Service Accounts (gMSAs) if they are added to a protected group (such as `Administrators` or `Domain Admins`), provided they are not members of an excluded group like `Domain Controllers` or `Read-Only Domain Controllers` (which are excluded to prevent replication and authentication breakages).

Therefore:
1. **Prevents Privilege Escalation Backdoors**: Auditing and hardening the `adminSDHolder` ACL ensures that unauthorized accounts cannot establish persistent, self-healing backdoors.
2. **Maintains Tier 0 Isolation**: Restricting write access on `adminSDHolder` strictly to Tier 0 accounts keeps the tiered boundary intact.
3. **Protects Against Inherited Backdoors**: Enforcing inheritance blocking on the `adminSDHolder` container prevents lateral permission leakage from parent containers.

---

## Legacy Impact & Compatibility
* **Administrative Operations**: If custom scripts or third-party provisioning systems rely on writing directly to protected accounts without belonging to the built-in protected groups, modifying the `adminSDHolder` ACL may disrupt their operations. Ensure all automated directory tools are audited before removing custom ACL entries.
* **Pre-Remediation Check**: Ensure that only trusted, built-in system groups (such as Domain Admins, Enterprise Admins, and SYSTEM) have Write and Modify permissions on the `adminSDHolder` object.
* **Service Accounts and gMSAs**: If service accounts or gMSAs are placed in administrative groups, their object DACLs will also be protected and set to block inheritance. Ensure this does not break service delegation or management permissions.

---

## Implementation Steps

### Option A: Active Directory Users and Computers (ADUC) Console Configuration

1. Open **Active Directory Users and Computers** (`dsa.msc`) on a Domain Controller.
2. Select **View** and click **Advanced Features** (if not already enabled).
3. Navigate to:
   `System\adminSDHolder`
4. Right-click **adminSDHolder** and select **Properties**.
5. Select the **Security** tab.
6. Click **Advanced**.
7. Enforce inheritance blocking:
   * Verify that the button at the bottom reads **Enable Inheritance**. If it reads **Disable Inheritance**, click it to block inheritance.
   * When prompted, choose to convert inherited permissions into explicit permissions to avoid losing default settings, then prune any non-compliant explicit permissions.
8. Review the permission entries:
   * Ensure only highly privileged built-in groups (e.g., `Domain Admins`, `Enterprise Admins`, `SYSTEM`) have Write, Modify, or Full Control permissions.
   * Remove any entries granting permissions to non-Tier 0 accounts, such as delegated helpdesk groups, `Account Operators`, `Print Operators`, or custom service accounts.
9. Click **OK** to save changes.

---

### Option B: PowerShell Configuration (Remediation / Non-GPO)

Run the following script to audit and remediate unauthorized permissions on the `adminSDHolder` object.

[Download Script: Harden-AdminSDHolder.ps1](implementation_scripts/Harden-AdminSDHolder.ps1)

```powershell
# Harden-AdminSDHolder.ps1
# Description: Hardens the adminSDHolder ACL by auditing permissions, blocking inheritance, and removing delegated helpdesk groups.

Import-Module ActiveDirectory

Write-Host "Applying hardening requirement: Harden adminSDHolder Permissions..." -ForegroundColor Cyan

# Set target DN
$DomainDN = (Get-ADRootDSE).defaultNamingContext
$AdminSDPath = "AD:\CN=adminSDHolder,CN=System,$($DomainDN)"

# Define allowed high-privilege built-in identities (SIDs or names)
$AllowedTrustees = @(
    "SYSTEM",
    "Domain Admins",
    "Enterprise Admins",
    "Administrators"
)

# Fetch ACL
$Acl = Get-Acl -Path $AdminSDPath
$AclModified = $false

# 1. Enforce inheritance blocking (DACL_Protected flag)
if ($Acl.AreAccessRulesProtected) {
    Write-Host "[+] Inheritance is already blocked (protected) on the adminSDHolder container." -ForegroundColor Green
} else {
    Write-Host "[-] adminSDHolder container has inheritance enabled. Blocking inheritance..." -ForegroundColor Yellow
    # Block inheritance ($true) and copy existing rules as explicit ($true)
    $Acl.SetAccessRuleProtection($true, $true)
    $AclModified = $true
}

# 2. Prune non-compliant permissions
foreach ($Rule in $Acl.Access) {
    $Identity = $Rule.IdentityReference.Value
    
    # Check if trustee is allowed to write
    if ($Rule.ActiveDirectoryRights -match "WriteProperty|WriteDacl|WriteOwner|GenericAll|GenericWrite") {
        $IsAllowed = $false
        foreach ($Allowed in $AllowedTrustees) {
            if ($Identity -match $Allowed) {
                $IsAllowed = $true
                break
            }
        }
        
        if (-not $IsAllowed) {
            Write-Host "[-] Unauthorized write permission found: Account '$($Identity)' has rights: $($Rule.ActiveDirectoryRights)" -ForegroundColor Yellow
            
            # Remove rule
            $Acl.RemoveAccessRule($Rule) | Out-Null
            $AclModified = $true
        }
    }
}

if ($AclModified) {
    Set-Acl -Path $AdminSDPath -AclObject $Acl -ErrorAction Stop
    Write-Host "[+] adminSDHolder ACL hardened successfully." -ForegroundColor Green
} else {
    Write-Host "[+] adminSDHolder ACL is already clean." -ForegroundColor Green
}
```

*To verify current adminSDHolder permissions:*
[Download Script: Get-AdminSDHolderAudit.ps1](audit_scripts/Get-AdminSDHolderAudit.ps1)

```powershell
# Get-AdminSDHolderAudit.ps1
# Description: Audits and prints all active permission entries and the inheritance block status on adminSDHolder.

Import-Module ActiveDirectory

Write-Host "--- Auditing adminSDHolder Permissions ---" -ForegroundColor Cyan

$DomainDN = (Get-ADRootDSE).defaultNamingContext
$AdminSDPath = "AD:\CN=adminSDHolder,CN=System,$($DomainDN)"
$Acl = Get-Acl -Path $AdminSDPath

# Check inheritance block status
if ($Acl.AreAccessRulesProtected) {
    Write-Host "[+] Inheritance is BLOCKED (Protected) on the adminSDHolder container (Secure)." -ForegroundColor Green
} else {
    Write-Host "[!] VULNERABLE: Inheritance is ENABLED (Unprotected) on the adminSDHolder container. Permissions may inherit from parent objects." -ForegroundColor Red
}

foreach ($Rule in $Acl.Access) {
    $Identity = $Rule.IdentityReference.Value
    $Rights = $Rule.ActiveDirectoryRights
    $Inheritance = $Rule.InheritanceType
    
    $Color = if ($Rights -match "WriteProperty|WriteDacl|WriteOwner|GenericAll") { "Yellow" } else { "Gray" }
    
    Write-Host "[*] Trustee: $($Identity)" -ForegroundColor White
    Write-Host "    - Rights: $($Rights)" -ForegroundColor $Color
    Write-Host "    - Inheritance: $($Inheritance)" -ForegroundColor Gray
}
```

---

## Sources & Compliance References
* **ANSSI Remediation of Active Directory Tier 0 Guide**: Section 5.d (Page 31)
* **ANSSI AD Hardening Guide**: Recommendation R23
* **Microsoft Security Guidance**: Protected Accounts and Groups in Active Directory
* **CIS Benchmark**: Section 2.2 (Active Directory Object Access Permissions)
* **SpecterOps Research**: AdminSDHolder: Misconceptions, Misconfigurations, and Myths (October 2025)

