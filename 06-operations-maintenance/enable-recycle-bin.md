# [REQ-OPS-002] Enable and Configure the Active Directory Recycle Bin

## Target Scope
* **Applicable Systems**: Domain Controllers (Forest-wide configuration affecting all domains)
* **Operating Systems**: Windows Server 2016, Windows Server 2019, Windows Server 2022, Windows Server 2025
* **Forest Functional Level**: Windows Server 2008 R2 or higher

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**: Active Directory Optional Features Configuration / Directory Service Configuration Container
  * **Optional Feature Identity**: `CN=Recycle Bin Feature,CN=Optional Features,CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,<ForestRootDN>`
  * **Directory Service Configuration Container**: `CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,<ForestRootDN>`
  * **Deleted Objects Container**: `CN=Deleted Objects,<DomainRootDN>`

---

## Rationale

The Active Directory (AD) Recycle Bin is an essential disaster recovery, availability, and incident response capability. In modern enterprise environments, directory availability is directly tied to core organizational operations. Accidental administrative errors, script bugs, malicious insider sabotage, and destructive cyberattacks (such as ransomware operations deploying wipers like HermeticWiper or deleting Tier 0 infrastructure to inhibit incident response) pose critical risks to Active Directory object integrity.

Enabling and properly configuring the Active Directory Recycle Bin provides vital security and operational defenses:

### 1. Active Directory Object Lifecycle Mechanics

Without the Recycle Bin, Active Directory relies on legacy tombstone reanimation. Under legacy reanimation, when an object is deleted, Active Directory immediately strips the majority of its attributes, and strips **all link-valued attributes** (such as group memberships (`memberOf`, `member`), manager/direct reports relationships, and delegated rights). Reanimating a tombstoned object restores only a stripped skeleton that requires extensive manual reconstruction, frequently resulting in security misconfigurations, lost access privileges, or unauthorized over-privilege.

When the Active Directory Recycle Bin is enabled, the object lifecycle transitions through four distinct stages:

```
+---------------+      Delete       +------------------+   msDS-deletedObjectLifetime   +-------------------+   tombstoneLifetime   +-------------------+
| Active Object | ----------------> |  Deleted Object  | -----------------------------> |  Recycled Object  | --------------------> | Purged / Removed  |
| (Normal OUs)  |                   | (isDeleted = $t) |            expires             | (isRecycled = $t) |        expires        | (Garbage Collect) |
+---------------+                   +------------------+                                +-------------------+                       +-------------------+
                                    - Preserves ALL attributes                          - Strips attributes                         - Record removed
                                    - Preserves ALL group links                         - Strips link tables                        from ntds.dit
                                    - Restorable via Recycle Bin                        - CANNOT be restored                        database
```

1. **Active Object**: The object resides in its standard Organizational Unit (OU) or container with full operational attributes and access rights.
2. **Deleted Object (`isDeleted = TRUE`)**: When deleted, the object moves to the `CN=Deleted Objects` container of its naming context. **All attributes, including link-valued attributes (group memberships, security identifiers, manager references), are preserved intact**. The object remains in this state for the duration defined by the Deleted Object Lifetime (`msDS-deletedObjectLifetime`, defaulting to `tombstoneLifetime`, typically 180 days). During this window, administrators can instantly restore the object to its exact previous state without data loss.
3. **Recycled Object (`isRecycled = TRUE`)**: Once the Deleted Object Lifetime expires, the object transitions to a recycled object. Active Directory strips most non-essential attributes and strips all link-valued attributes. The object remains in this state for the remainder of the tombstone lifetime (`tombstoneLifetime`). In this state, the object **cannot be restored** using the Recycle Bin or reanimation tools.
4. **Purged Object**: When the tombstone lifetime expires while in the recycled state, the garbage collection process (running every 12 hours by default on each Domain Controller) physically removes the object record from the Active Directory database (`ntds.dit`).

### 2. Threat Vectors Mitigated

* **Ransomware & Wiper Sabotage**: Adversaries frequently execute bulk deletion scripts targeting critical organizational units, computer accounts, service accounts, and Group Policy Objects to disrupt operations, force enterprise collapse, or blind defensive monitoring tools. The Recycle Bin enables rapid restoration within minutes rather than days.
* **Covering Tracks & Account Erasure**: Attackers who create rogue administrative accounts or compromise legitimate users may delete those accounts prior to eviction to impede digital forensics and incident triage. The Recycle Bin preserves the deleted objects along with their historical metadata, security identifiers (SIDs), and linkage attributes, allowing incident responders to examine deleted artifacts.
* **Administrative Scripting Accidents**: Mass-deletions caused by unverified automated decommissioning scripts or human error can be recovered instantaneously without incurring directory downtime or taking Domain Controllers offline.

### 3. Protection of the `CN=Deleted Objects` Container

The `CN=Deleted Objects` container stores deleted directory objects, which may contain sensitive historical information, including previous user names, employee numbers, descriptions, SIDs, and password history hashes. By default, Active Directory restricts access to this container to `NT AUTHORITY\SYSTEM` and members of `BUILTIN\Administrators` (and `Enterprise Admins` in the forest root).

Ensuring that default permissions on `CN=Deleted Objects` are strictly enforced prevents unprivileged users from enumerating deleted objects or harvesting sensitive operational intelligence. Furthermore, delegating object restoration requires specific granular rights (`Reanimate Tombstone` control access right: `05c634f3-2e50-11d2-834f-0000f87a39f2`) rather than granting broad administrative privileges.

### 4. Boundary Between Recycle Bin and System State Backups

The Active Directory Recycle Bin is an **online object recovery mechanism**, not an offline disaster recovery replacement:
* **Recycle Bin Covers**: Accidental or malicious deletion of individual or bulk directory objects (users, groups, OUs, computers, service accounts) while directory replication and the database remain online.
* **System State Backups Cover**: Catastrophic database corruption, physical disk failure, Active Directory schema corruption, unauthorized forest-wide configuration tampering, or ransomware encryption of Domain Controller operating systems.
Organizations must implement both the Active Directory Recycle Bin and regular System State Backups (see [REQ-OPS-008](configure-system-state-backups.md)) for comprehensive defense-in-depth.

---

## Legacy Impact & Compatibility

* **Permanent and Irreversible Operation**: Enabling the Active Directory Recycle Bin is an irreversible forest-wide action. Once the optional feature is enabled, it cannot be disabled or rolled back.
* **Forest Functional Level Requirement**: The Forest Functional Level (FFL) must be at least Windows Server 2008 R2. All Domain Controllers in all domains of the forest must run an operating system version capable of supporting this functional level.
* **Database Sizing (`ntds.dit`)**: Because deleted objects retain all attributes and link-valued tables for the duration of the Deleted Object Lifetime (typically 180 days), the Active Directory database will not immediately reclaim disk space upon object deletion. In high-turnover environments (such as organizations with rapid automated onboarding/offboarding), ensure Domain Controller storage volumes have at least 15% to 25% free disk headroom.
* **Replication Overhead**: Enabling the Recycle Bin and restoring large batches of objects generates replication traffic across domain controllers. In multi-site topologies with bandwidth-constrained WAN links, schedule large-scale recovery operations with replication topology awareness.

---

## Implementation Steps

### Option A: Active Directory Administrative Center (GUI Configuration & Recovery)

#### 1. Enabling the Recycle Bin (Forest Root Domain Controller)

1. Log on to a Domain Controller in the forest root domain with an account that is a member of the **Enterprise Admins** group.
2. Open **Active Directory Administrative Center** (`dsac.exe`).
3. In the left navigation pane, select the forest root domain node.
4. In the right-hand **Tasks** pane, click **Enable Recycle Bin...**.
5. In the confirmation warning dialog informing that this action is irreversible, click **OK**.
6. A notification dialog will state that the feature will begin replicating across all Domain Controllers in the forest. Click **OK**.
7. Refresh the Administrative Center interface; the "Enable Recycle Bin..." link will now be permanently grayed out.

#### 2. Restoring Deleted Objects via ADAC

1. Open **Active Directory Administrative Center** (`dsac.exe`).
2. In the left navigation pane, expand the target domain node and click on the **Deleted Objects** container.
3. Locate the deleted object(s) using the search bar or filter criteria.
4. Right-click the object and select one of the following options:
   * **Restore**: Restores the object directly to its original parent Organizational Unit.
   * **Restore To...**: Allows specifying an alternative target Organizational Unit (required if the original parent OU was deleted or relocated).

---

### Option B: PowerShell & Directory Configuration (Remediation / Non-GPO)

Run the following scripts to audit and activate the optional feature forest-wide, configure retention lifetimes, and verify container security.

#### 1. Local Audit (Audit-ADRecycleBin.ps1)

[Download Script: Audit-ADRecycleBin.ps1](audit_scripts/Audit-ADRecycleBin.ps1)

```powershell
# Audit-ADRecycleBin.ps1
# Description: Audits Active Directory Recycle Bin status, lifetime configurations, and container ACL permissions.
# Target Engine: Windows PowerShell 5.1

Write-Host "--- Auditing Active Directory Recycle Bin Configuration ---" -ForegroundColor Cyan

$isVulnerable = $false

# 1. Verify Active Directory module availability
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Host "VULNERABLE: The ActiveDirectory PowerShell module is not available on this system." -ForegroundColor Red
    Write-Host "Audit Result: VULNERABLE" -ForegroundColor Red
    return
}

Import-Module ActiveDirectory -ErrorAction SilentlyContinue

try {
    # 2. Check Forest and Forest Functional Level
    $forest = Get-ADForest -ErrorAction Stop
    $forestMode = $forest.ForestMode

    Write-Host "[*] Active Directory Forest: $($forest.Name)" -ForegroundColor Gray
    Write-Host "[*] Forest Functional Level: $($forestMode)" -ForegroundColor Gray

    $validModes = @("Windows2008R2Forest", "Windows2012Forest", "Windows2012R2Forest", "Windows2016Forest", "Windows2025Forest")
    if ($validModes -notcontains $forestMode) {
        Write-Host "VULNERABLE: Forest Functional Level '$($forestMode)' does not support Active Directory Recycle Bin (requires Windows Server 2008 R2 or higher)." -ForegroundColor Red
        $isVulnerable = $true
    }

    # 3. Check Optional Feature Enablement
    $recycleFeature = Get-ADOptionalFeature -Filter "Name -eq 'Recycle Bin Feature'" -Properties EnabledScopes -ErrorAction Stop
    $enabledScopes = $recycleFeature.EnabledScopes

    if ($enabledScopes -and ($enabledScopes -contains $forest.PartitionsContainer -or $enabledScopes.Count -gt 0)) {
        Write-Host "[+] Recycle Bin Feature is ENABLED forest-wide." -ForegroundColor Green
    } else {
        Write-Host "VULNERABLE: Active Directory Recycle Bin Feature is NOT enabled in forest '$($forest.Name)'." -ForegroundColor Red
        $isVulnerable = $true
    }

    # 4. Check Deleted Object Lifetime and Tombstone Lifetime
    $rootDse = Get-ADRootDSE -ErrorAction Stop
    $configNC = $rootDse.configurationNamingContext
    $dsPath = "CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,$configNC"

    $dsConfig = Get-ADObject -Identity $dsPath -Properties msDS-deletedObjectLifetime, tombstoneLifetime -ErrorAction Stop
    $dol = $dsConfig."msDS-deletedObjectLifetime"
    $tombstone = $dsConfig.tombstoneLifetime

    if ($null -eq $tombstone -or $tombstone -eq 0) {
        $effectiveTombstone = 60 # Legacy Windows 2000/2003 default
        Write-Host "[!] tombstoneLifetime attribute is not explicitly set (defaults to 60 days in legacy forests, or 180 days in modern forests)." -ForegroundColor Yellow
    } else {
        $effectiveTombstone = $tombstone
        Write-Host "[*] tombstoneLifetime: $($effectiveTombstone) days" -ForegroundColor Gray
    }

    if ($null -eq $dol) {
        Write-Host "[*] msDS-deletedObjectLifetime: (Not Set - defaults to tombstoneLifetime of $($effectiveTombstone) days)" -ForegroundColor Gray
    } else {
        Write-Host "[*] msDS-deletedObjectLifetime: $($dol) days" -ForegroundColor Gray
        if ($dol -lt 60) {
            Write-Host "VULNERABLE: msDS-deletedObjectLifetime is configured to less than 60 days ($($dol) days). Recovery window is excessively short." -ForegroundColor Red
            $isVulnerable = $true
        }
    }

    # 5. Audit Access Permissions on CN=Deleted Objects Container
    $domainDN = $rootDse.defaultNamingContext
    $deletedObjectsDN = "CN=Deleted Objects,$domainDN"

    Write-Host "[*] Auditing security permissions on: $($deletedObjectsDN)" -ForegroundColor Gray

    try {
        $deletedObjACL = Get-Acl -Path "AD:\$deletedObjectsDN" -ErrorAction Stop
        $suspiciousIdentities = @(
            "NT AUTHORITY\Authenticated Users",
            "Everyone",
            "BUILTIN\Users",
            "ANONYMOUS LOGON"
        )

        $flaggedAccess = $false
        foreach ($accessRule in $deletedObjACL.Access) {
            $identity = $accessRule.IdentityReference.Value
            foreach ($suspicious in $suspiciousIdentities) {
                if ($identity -like "*$suspicious*" -and $accessRule.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow) {
                    Write-Host "VULNERABLE: Non-default permissive access granted to '$($identity)' on Deleted Objects container ($($accessRule.ActiveDirectoryRights))." -ForegroundColor Red
                    $flaggedAccess = $true
                    $isVulnerable = $true
                }
            }
        }

        if (-not $flaggedAccess) {
            Write-Host "[+] Permissions on Deleted Objects container are restricted to privileged administrators." -ForegroundColor Green
        }
    } catch {
        Write-Host "[*] Note: Unable to query Deleted Objects container ACL directly ($($_.Exception.Message))." -ForegroundColor Yellow
    }

} catch {
    Write-Host "VULNERABLE: Failed to complete Active Directory Recycle Bin audit. Error: $($_.Exception.Message)" -ForegroundColor Red
    $isVulnerable = $true
}

Write-Host "--------------------------------------------------------" -ForegroundColor Cyan
if ($isVulnerable) {
    Write-Host "Audit Result: VULNERABLE - Active Directory Recycle Bin configuration requires remediation." -ForegroundColor Red
} else {
    Write-Host "Audit Result: SECURE - Active Directory Recycle Bin is enabled and correctly configured." -ForegroundColor Green
}
```

#### 2. Local Remediation (Enable-ADRecycleBin.ps1)

[Download Script: Enable-ADRecycleBin.ps1](implementation_scripts/Enable-ADRecycleBin.ps1)

```powershell
# Enable-ADRecycleBin.ps1
# Description: Validates forest prerequisites, enables Active Directory Recycle Bin forest-wide, and configures lifetimes.
# Target Engine: Windows PowerShell 5.1

Write-Host "--- Applying Hardening Requirement: Enable Active Directory Recycle Bin ---" -ForegroundColor Cyan

# 1. Verify Active Directory module
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Error "The ActiveDirectory PowerShell module is required to execute this script."
    return
}

Import-Module ActiveDirectory -ErrorAction Stop

try {
    # 2. Forest and FFL Validation
    $forest = Get-ADForest -ErrorAction Stop
    $forestMode = $forest.ForestMode

    Write-Host "[*] Target Forest: $($forest.Name)" -ForegroundColor Gray
    Write-Host "[*] Current Forest Functional Level: $($forestMode)" -ForegroundColor Gray

    $validModes = @("Windows2008R2Forest", "Windows2012Forest", "Windows2012R2Forest", "Windows2016Forest", "Windows2025Forest")
    if ($validModes -notcontains $forestMode) {
        Write-Error "Cannot enable Recycle Bin. Forest functional level must be Windows Server 2008 R2 or higher (Current: $($forestMode)). Raise forest functional level first."
        return
    }

    # 3. Check and Enable Recycle Bin Feature
    $recycleBinFeature = Get-ADOptionalFeature -Filter "Name -eq 'Recycle Bin Feature'" -ErrorAction Stop
    $enabledScopes = $recycleBinFeature.EnabledScopes

    if (-not $enabledScopes -or $enabledScopes.Count -eq 0) {
        Write-Host "[+] Enabling Active Directory Recycle Bin optional feature in forest '$($forest.Name)'..." -ForegroundColor Yellow
        Enable-ADOptionalFeature -Identity $recycleBinFeature -Scope ForestOrConfigurationSet -Target $forest.Name -Confirm:$false -ErrorAction Stop
        Write-Host "[+] Active Directory Recycle Bin enabled successfully." -ForegroundColor Green
    } else {
        Write-Host "[+] Active Directory Recycle Bin is already enabled in forest '$($forest.Name)'." -ForegroundColor Green
    }

    # 4. Configure / Verify msDS-deletedObjectLifetime
    $rootDse = Get-ADRootDSE -ErrorAction Stop
    $configNC = $rootDse.configurationNamingContext
    $dsPath = "CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,$configNC"

    $dsConfig = Get-ADObject -Identity $dsPath -Properties msDS-deletedObjectLifetime, tombstoneLifetime -ErrorAction Stop
    $tombstone = $dsConfig.tombstoneLifetime
    $currentDol = $dsConfig."msDS-deletedObjectLifetime"

    # Ensure tombstoneLifetime is at least 180 days
    if ($null -eq $tombstone -or $tombstone -lt 180) {
        Write-Host "[+] Setting tombstoneLifetime to 180 days on Directory Service configuration..." -ForegroundColor Yellow
        Set-ADObject -Identity $dsPath -Replace @{ tombstoneLifetime = 180 } -ErrorAction Stop
        Write-Host "[+] tombstoneLifetime updated to 180 days." -ForegroundColor Green
    } else {
        Write-Host "[+] tombstoneLifetime is currently configured to $($tombstone) days." -ForegroundColor Green
    }

    # Set explicit msDS-deletedObjectLifetime if missing or excessively low
    if ($null -eq $currentDol -or $currentDol -lt 180) {
        Write-Host "[+] Explicitly configuring msDS-deletedObjectLifetime to 180 days..." -ForegroundColor Yellow
        Set-ADObject -Identity $dsPath -Replace @{ "msDS-deletedObjectLifetime" = 180 } -ErrorAction Stop
        Write-Host "[+] msDS-deletedObjectLifetime configured to 180 days." -ForegroundColor Green
    } else {
        Write-Host "[+] msDS-deletedObjectLifetime is currently set to $($currentDol) days." -ForegroundColor Green
    }

    Write-Host "[+] Remediation completed successfully. Allow directory replication to synchronize across all Domain Controllers." -ForegroundColor Green

} catch {
    Write-Error "Failed to configure Active Directory Recycle Bin. Error: $($_.Exception.Message)"
}
```

---

### Option C: Operational Recovery Runbook (PowerShell)

Use these commands during incident response or accidental deletion triage to locate and restore deleted objects.

#### 1. Discovering Deleted Objects

```powershell
# List all deleted objects in the domain
Get-ADObject -SearchBase "CN=Deleted Objects,$((Get-ADRootDSE).defaultNamingContext)" -IncludeDeletedObjects -Filter 'isDeleted -eq $true' -Properties sAMAccountName, whenChanged, lastKnownParent, objectClass

# Find a deleted user by username
Get-ADObject -Filter "sAMAccountName -eq 'jsmith' -and isDeleted -eq $true" -IncludeDeletedObjects -Properties sAMAccountName, lastKnownParent

# Find all objects deleted within the last 24 hours
$cutoff = (Get-Date).AddDays(-1)
Get-ADObject -Filter "whenChanged -ge `$cutoff -and isDeleted -eq `$true" -IncludeDeletedObjects -Properties sAMAccountName, whenChanged, lastKnownParent
```

#### 2. Restoring a Single Deleted Object

```powershell
# Restore a user object back to its original location (lastKnownParent)
Get-ADObject -Filter "sAMAccountName -eq 'jsmith' -and isDeleted -eq $true" -IncludeDeletedObjects | Restore-ADObject

# Restore an object to an alternative Organizational Unit
$targetOU = "OU=Quarantine,DC=corp,DC=domain,DC=com"
Get-ADObject -Filter "sAMAccountName -eq 'jsmith' -and isDeleted -eq $true" -IncludeDeletedObjects | Restore-ADObject -TargetPath $targetOU
```

#### 3. Restoring Nested Organizational Units and Dependent Child Objects

When an Organizational Unit containing child objects (sub-OUs, users, groups, computers) is deleted, all objects move directly into `CN=Deleted Objects`. Because child objects reference their parent container, **the parent Organizational Unit must be restored first**, followed by subordinate child objects in hierarchical order:

```powershell
# Step 1: Restore the parent Organizational Unit first
Get-ADObject -Filter "objectClass -eq 'organizationalUnit' -and name -like 'Finance*' -and isDeleted -eq $true" -IncludeDeletedObjects | Restore-ADObject

# Step 2: Restore child objects (users, groups, computers) once parent OU exists
Get-ADObject -Filter "lastKnownParent -like '*Finance*' -and isDeleted -eq $true" -IncludeDeletedObjects | Restore-ADObject
```

---

## Security Auditing & Monitoring

Ensure that Active Directory change and access events are recorded and ingested into the centralized SIEM solution:

| Event ID | Log Provider | Event Description | Security Relevance |
| :--- | :--- | :--- | :--- |
| **5136** | Security | A directory service object was modified | Triggered when `isDeleted` attribute is set to `TRUE`, or when attributes are restored. |
| **5137** | Security | A directory service object was created | Triggered upon directory object creation. |
| **5139** | Security | A directory service object was moved | Triggered when an object is moved into or out of `CN=Deleted Objects` during deletion or restoration. |
| **5141** | Security | A directory service object was deleted | Generated when an object is moved to the deleted state. |
| **4662** | Security | An operation was performed on an object | Monitors invocations of the `Reanimate Tombstone` extended right (`05c634f3-2e50-11d2-834f-0000f87a39f2`). |
| **1699** | Directory Service | Optional Feature status change | Records the forest-wide enablement of optional features such as the Recycle Bin. |

---

## Sources & Compliance References

* **ANSSI AD Hardening Guide**: Recommendation R54 (Establish secure Domain Controller backup and disaster recovery)
* **Microsoft Best Practices**: Active Directory Recycle Bin Step-by-Step Guide
* **MITRE ATT&CK Framework**:
  * **T1485**: Data Destruction (mitigated via instant object recovery)
  * **T1489**: Service Stop (denial of service through object deletion)
  * **T1070**: Indicator Removal on Host (retains deleted object artifacts for triage)
* **NIST SP 800-53 Rev. 5**:
  * **CP-9**: System Backup
  * **CP-10**: Information System Recovery and Reconstitution
  * **SI-12**: Information Management and Retention
