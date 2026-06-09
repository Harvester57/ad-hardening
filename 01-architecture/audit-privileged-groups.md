# Hardening Requirement: Audit Privileged Groups

## Target Scope
* **Applicable Systems**: Active Directory Domain.
* **Operating Systems**: Windows Server 2016 (and above) Domain Controllers.

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * Active Directory Directory Service Changes Auditing (GPO: Computer Configuration\Policies\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies\DS Access)

---

## Rationale
Attackers who gain initial access to an Active Directory domain attempt to elevate their privileges to Tier 0. A primary method for establishing domain persistence is adding compromised domain accounts to highly privileged administrative groups, such as `Domain Admins`, `Enterprise Admins`, `Schema Admins`, or `Builtin\Administrators`.

If these groups are not audited continuously:
1. **Backdoor Persistence**: Attackers can add temporary users to administrative groups and remove them later, leaving backdoor accounts with administrative authority that go unnoticed.
2. **Privilege Creep**: Unmanaged administrative accounts accumulate over time, violating the principle of least privilege.
3. **Delegation Risks**: Administrative accounts can inherit unintended administrative rights if nested within other groups.

Enforcing advanced auditing on directory object changes, combined with a daily script to monitor privileged group members, ensures immediate visibility into unauthorized modifications.

---

## Legacy Impact & Compatibility
* **Auditing Load**: Directory Service changes logging (Event ID 5136) can generate a high volume of events on Domain Controllers in large environments. Ensure event logs have appropriate size allocations and logs are shipped to a local SIEM.
* **Operational Workflows**: Administrators must use standard change management procedures when adding or removing accounts from administrative groups to avoid generating false-positive security alerts.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

To generate events when administrative group membership is altered:
1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Create or edit the GPO linked to the **Domain Controllers** OU (e.g., `GPO_Hardening_DomainControllers`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies\DS Access`
4. Configure the setting:
   * **Policy**: `Audit Directory Service Changes`
   * **Setting**: `Enabled` (Select `Success` and `Failure`)

This ensures that Event ID **5136** is logged in the Security log of the Domain Controller whenever an Active Directory object attribute (such as a group's `member` attribute) is changed.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run this script from a secure administrative workstation to audit nested and direct memberships in critical Tier 0 groups, highlighting any unexpected accounts.

```powershell
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
```

*To verify that directory auditing is active on the local DC:*
```powershell
# Test-ADChangesAuditing.ps1
# Audits local DC auditpol settings to verify Directory Service auditing is enabled.

Write-Host "--- Auditing Directory Service Audit Policy ---" -ForegroundColor Cyan

$rawOutput = auditpol.exe /get /subcategory:"Directory Service Changes" /r
# Parse CSV output: Machine,Subcategory,GUID,PolicyVal
if ($rawOutput -match "^.+,Directory Service Changes,.+,(.+)$") {
    $policyVal = $Matches[1]
    $color = if ($policyVal -match "Success") { "Green" } else { "Red" }
    Write-Host "    - Directory Service Changes Audit: $policyVal (Required = Success and Failure)" -ForegroundColor $color
} else {
    Write-Warning "    - Status: Could not parse DS auditpol status."
}
```

---

## 🔗 Sources & Compliance References
* **ANSSI AD Hardening Guide**: Recommendation R57 (Vulnerability assessment of directory services), Section on administrative groups.
* **CIS Microsoft Windows Server 2016 Benchmark**: Section 9.2.1 (Audit Directory Service Access)
* **Microsoft Security Baselines**: Domain Controller baseline settings.
