# [REQ-ARCH-007] Harden Microsoft Exchange Active Directory Permissions

## Target Scope
* **Applicable Systems**: Active Directory Domain Controllers and Domain Root Object (Tier 0).
* **Operating Systems**: Active Directory Domain Services (All supported functional levels).

---

## Implementation Details
* **Priority**: High (Prevents domain-wide privilege escalation from compromised Exchange servers).
* **GPO Path / Registry Location**: N/A (Direct Active Directory ACL modification on the domain root object).

---

## Rationale
By default, installing Microsoft Exchange Server in an Active Directory forest modifies the permissions of the domain root object. It grants the **Exchange Windows Permissions** group (and sometimes **Exchange Servers**) write permissions (`WriteDacl` and `WriteOwner`) over the domain root container.

This configuration presents a critical security risk:
1. **Privilege Escalation**: Any user or service account with administrative control over Exchange, or any compromised Exchange server itself, can write new permissions to the domain root.
2. **DCSync Exploitation**: The attacker can grant their own account the `ds-Replication-Get-Changes` and `ds-Replication-Get-Changes-All` (DCSync) extended rights. This allows the attacker to dump password hashes directly from the domain controller database (NTDS.dit), leading to a complete forest compromise.

Restricting these write permissions ensures that Exchange servers cannot modify domain-level security descriptors.

---

## Legacy Impact & Compatibility
* **Exchange Operations**: Restricting `WriteDacl` on the domain root may prevent Exchange from performing certain automatic administrative operations, such as modifying schema attributes, auto-provisioning objects in default containers, or updating domain-wide permissions during subsequent Exchange cumulative updates (CUs).
* **Workaround**: If Exchange database or organization adjustments are required, a member of the Domain Admins or Enterprise Admins group must run Exchange setup with the `/PrepareAD` flag to temporarily apply permissions, or perform the modifications manually.

---

## Implementation Steps

### Option A: Active Directory Users & Computers (GUI Configuration)

1. Open **Active Directory Users and Computers** (`dsa.msc`) on a management console with Domain Admin privileges.
2. Enable **Advanced Features** under the **View** menu.
3. Right-click the root domain object (e.g., `domain.local`) and select **Properties**.
4. Select the **Security** tab, then click **Advanced**.
5. Locate the permission entries for **Exchange Windows Permissions** and **Exchange Servers**.
6. Review the permissions:
   * Remove any entries granting **Modify permissions** (`WriteDacl`) or **Modify owner** (`WriteOwner`) on the domain root.
   * Ensure standard read and object creation permissions (such as writing specific user properties for mailbox management) remain unchanged.
7. Click **Apply**, then **OK**.

---

### Option B: PowerShell & Active Directory Configuration (Remediation / Non-GPO)

To automate verification and remediation of the domain root ACL:

[Download Script: Harden-ExchangePermissions.ps1](implementation_scripts/Harden-ExchangePermissions.ps1)

```powershell
# Harden-ExchangePermissions.ps1
# Description: Removes WriteDacl and WriteOwner permissions for Exchange groups on the domain root.

Import-Module ActiveDirectory

$DomainDN = (Get-ADDomain).DistinguishedName
$DomainPath = "AD:\$DomainDN"

# Retrieve existing ACL
$Acl = Get-Acl -Path $DomainPath
$DangerousAcesToRemove = @()

# Define Exchange groups to target
$TargetGroups = @("Exchange Windows Permissions", "Exchange Servers")
$TargetSids = @()

foreach ($groupName in $TargetGroups) {
    try {
        $sid = (Get-ADGroup -Identity $groupName).SID.Value
        $TargetSids += $sid
    }
    catch {
        Write-Host "Group '$groupName' not found in this domain. Skipping." -ForegroundColor Yellow
    }
}

if ($TargetSids.Count -eq- 0) {
    Write-Host "No Exchange groups detected. No permissions to harden." -ForegroundColor Green
    exit 0
}

# Scan ACL for dangerous ACEs
foreach ($ace in $Acl.Access) {
    $identity = $ace.IdentityReference
    try {
        $sid = $identity.Translate([System.Security.Principal.SecurityIdentifier]).Value
    }
    catch {
        continue
    }

    if ($TargetSids -contains $sid) {
        # Check for WriteDacl or WriteOwner rights
        $hasWriteDacl = ($ace.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl) -eq [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl
        $hasWriteOwner = ($ace.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteOwner) -eq [System.DirectoryServices.ActiveDirectoryRights]::WriteOwner

        if ($hasWriteDacl -or $hasWriteOwner) {
            $DangerousAcesToRemove += $ace
        }
    }
}

if ($DangerousAcesToRemove.Count -eq 0) {
    Write-Host "[+] Domain root ACL is compliant. No dangerous Exchange write permissions found." -ForegroundColor Green
} else {
    Write-Host "[-] Found $($DangerousAcesToRemove.Count) dangerous Exchange permissions. Removing..." -ForegroundColor Yellow
    foreach ($ace in $DangerousAcesToRemove) {
        $Acl.RemoveAccessRule($ace) | Out-Null
    }
    Set-Acl -Path $DomainPath -AclObject $Acl
    Write-Host "[+] Successfully removed dangerous Exchange WriteDacl/WriteOwner permissions from domain root." -ForegroundColor Green
}
```

*To verify the domain root permissions:*

[Download Script: Get-ExchangePermissionsStatus.ps1](audit_scripts/Get-ExchangePermissionsStatus.ps1)

```powershell
# Get-ExchangePermissionsStatus.ps1
# Check if Exchange groups hold WriteDacl/WriteOwner permissions on the domain root.

Import-Module ActiveDirectory

$DomainDN = (Get-ADDomain).DistinguishedName
$DomainPath = "AD:\$DomainDN"

$Acl = Get-Acl -Path $DomainPath
$TargetGroups = @("Exchange Windows Permissions", "Exchange Servers")
$TargetSids = @()

foreach ($groupName in $TargetGroups) {
    try {
        $sid = (Get-ADGroup -Identity $groupName).SID.Value
        $TargetSids += $sid
    }
    catch {
        # Group not present in domain
    }
}

if ($TargetSids.Count -eq 0) {
    Write-Host "[+] COMPLIANT: Exchange groups are not present in this domain."
    exit 0
}

$nonCompliantAces = 0

foreach ($ace in $Acl.Access) {
    $identity = $ace.IdentityReference
    try {
        $sid = $identity.Translate([System.Security.Principal.SecurityIdentifier]).Value
    }
    catch {
        continue
    }

    if ($TargetSids -contains $sid) {
        $hasWriteDacl = ($ace.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl) -eq [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl
        $hasWriteOwner = ($ace.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteOwner) -eq [System.DirectoryServices.ActiveDirectoryRights]::WriteOwner

        if ($hasWriteDacl -or $hasWriteOwner) {
            Write-Host "[!] NON-COMPLIANT: Group '$($identity.Value)' has permissions: $($ace.ActiveDirectoryRights)" -ForegroundColor Red
            $nonCompliantAces++
        }
    }
}

if ($nonCompliantAces -eq 0) {
    Write-Host "[+] COMPLIANT: No Exchange groups have WriteDacl or WriteOwner permissions on the domain root." -ForegroundColor Green
    exit 0
} else {
    Write-Host "[!] NON-COMPLIANT: Dangerous Exchange write permissions detected on the domain root." -ForegroundColor Red
    exit 1
}
```

---

## Sources & Compliance References
* **ANSSI AD Hardening Guide**: Recommendation R13 (Restricting permissions on domain objects)
* **CIS Benchmark**: Section 1.2 (Active Directory Permissions Audit)
* **PingCastle Rule**: `P-ExchangePrivEsc` (Ensure that Exchange did not introduce security vulnerabilities)
