# Hardening Requirement: Restrict Schema Administrators Group Membership

## Target Scope
* **Applicable Systems**: Domain Controllers
* **Operating Systems**: Windows Server 2016 and above

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**: `Computer Configuration\Policies\Windows Settings\Security Settings\Restricted Groups`

---

## Rationale
The Schema Admins group is one of the most critical security groups within an Active Directory forest. This group controls the underlying structure of the directory database, defining every class of object and every attribute that those objects can possess.

A compromised Schema Admin account poses a massive risk to the forest:
1. **Schema Modifications**: Attackers can modify class definitions, introduce rogue attributes, or insert persistent directory-level backdoors that survive standard OS-level remediation.
2. **Low Operational Frequency**: Schema modifications are extremely rare, typically occurring only during major enterprise software installations (such as Exchange, SCCM) or AD functional level upgrades.

To minimize the attack surface, standard administrative accounts must not have permanent membership in the Schema Admins group. Instead, membership must be granted strictly on a Just-In-Time (JIT) basis and revoked immediately after schema changes are completed. Locking the group membership to empty using a Restricted Groups GPO ensures that any unauthorized or accidental additions are automatically cleared.

---

## Legacy Impact & Compatibility
* **Schema Updates Blocked**: When executing legitimate schema updates, the Restricted Groups GPO will automatically remove installers from the group, causing setup failures. During scheduled upgrades, administrators must temporarily disable the link for this GPO (or modify the policy) and enable it immediately once the upgrade completes.
* **Administrative Training**: Administrators must be trained on JIT procedures for schema changes.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Log on to a management workstation or Domain Controller with **Domain Admins** credentials.
2. Open the **Group Policy Management Console** (`gpmc.msc`).
3. Create a new GPO named `SEC_Forest_RestrictedGroups` and link it to the **Domain Controllers** OU in the forest root domain.
4. Right-click the GPO and select **Edit** to open the Group Policy Management Editor.
5. Navigate to:
   `Computer Configuration > Policies > Windows Settings > Security Settings > Restricted Groups`
6. Right-click **Restricted Groups** and select **Add Group**.
7. In the Group box, type or browse for **Schema Admins** and click **OK**.
8. In the properties dialog for Schema Admins:
   * Leave the list under **Members of this group** completely blank.
   * Leave the list under **This group is a member of** completely blank.
9. Click **Apply** and **OK**.
10. The group membership will be automatically checked and cleared on Domain Controllers during Group Policy refresh cycles.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following scripts to audit and clear the group membership.

#### 1. Local Audit (Audit-SchemaAdminsGroup.ps1)

[Download Script: Audit-SchemaAdminsGroup.ps1](audit_scripts/Audit-SchemaAdminsGroup.ps1)

```powershell
# Audit-SchemaAdminsGroup.ps1
# Description: Audits the Schema Admins group membership.

Import-Module ActiveDirectory

Write-Host "--- Auditing Schema Admins Group Membership ---" -ForegroundColor Cyan

try {
    $Group = Get-ADGroup -Identity "Schema Admins" -Properties Members -ErrorAction Stop
    $MembersCount = $Group.Members.Count
    
    if ($MembersCount -gt 0) {
        Write-Host "`nVULNERABLE: Schema Admins group is NOT empty. Found $MembersCount member(s):" -ForegroundColor Red
        foreach ($memberDN in $Group.Members) {
            $memberObj = Get-ADObject -Identity $memberDN -ErrorAction SilentlyContinue
            Write-Host "    - Member: $($memberObj.Name) | DN: $memberDN" -ForegroundColor White
        }
    } else {
        Write-Host "`nStatus: Compliant. Schema Admins group is empty." -ForegroundColor Green
    }
} catch {
    Write-Host "VULNERABLE: Could not query Schema Admins group. Error: $($_.Exception.Message)" -ForegroundColor Red
}
```

#### 2. Local Remediation (Clear-SchemaAdminsGroup.ps1)

[Download Script: Clear-SchemaAdminsGroup.ps1](implementation_scripts/Clear-SchemaAdminsGroup.ps1)

```powershell
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
```

---

## Sources & Compliance References
* **ANSSI AD Hardening Guide**: Technical recommendations regarding privileged group membership management.
* **Microsoft Architecture Guide**: Design recommendations for administrative group hygiene.
