# Hardening Requirement: Enable and Configure the Active Directory Recycle Bin

## Target Scope
* **Applicable Systems**: Domain Controllers (Forest-wide configuration)
* **Operating Systems**: Windows Server 2016 and above

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**: Active Directory Optional Features Configuration

---

## Rationale
The Active Directory (AD) Recycle Bin is a critical availability and recovery component in an enterprise environment. It addresses risks related to accidental deletions, administrative scripting errors, and malicious insider sabotage targeting directory objects.

Enabling this feature provides several key benefits:
1. **Preserving Object State**: Unlike legacy "tombstone reanimation", the AD Recycle Bin preserves all link-valued attributes (such as group memberships, manager relationships, and direct reports) of deleted objects. When an object is restored, its security context and access privileges are reinstated exactly as they were, preventing security gaps associated with manual reconstruction.
2. **Operational Efficiency**: It allows administrators to restore objects without taking a Domain Controller offline to perform a Directory Services Restore Mode (DSRM) authoritative restore. This reduces downtime and maintains service availability.
3. **Data Lifecycle Alignment**: By explicitly defining the Deleted Object Lifetime (DOL), organizations ensure that deleted items are retained for a designated period before permanent sanitization.

---

## Legacy Impact & Compatibility
* **Irreversibility**: Enabling the Active Directory Recycle Bin is a permanent forest-wide action that cannot be disabled once activated.
* **Functional Level Pre-requisite**: The Forest Functional Level must be Windows Server 2008 R2 or higher.
* **Database Size**: Enabling the Recycle Bin increases the size of the Active Directory database (`ntds.dit`) because deleted objects are not immediately stripped of their attributes. Ensure Domain Controllers have sufficient storage space.

---

## Implementation Steps

### Option A: Active Directory Administrative Center (Preferred)

1. Log on to a Domain Controller with **Enterprise Admins** credentials.
2. Open **Active Directory Administrative Center** (`dsac.exe`).
3. In the left navigation pane, select the local domain name.
4. In the **Tasks** pane on the right side, click **Enable Recycle Bin...**.
5. In the confirmation warning dialog, click **OK**.
6. A notification dialog will state that the change will begin replicating across all Domain Controllers in the forest. Click **OK**.
7. Refresh the Administrative Center interface; the "Enable Recycle Bin..." link will now be grayed out.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following scripts to audit and activate the optional feature forest-wide.

#### 1. Local Audit (Audit-ADRecycleBin.ps1)

```powershell
# Audit-ADRecycleBin.ps1
# Description: Audits the enablement status of the AD Recycle Bin.

Import-Module ActiveDirectory

Write-Host "--- Auditing Active Directory Recycle Bin ---" -ForegroundColor Cyan

try {
    $Forest = Get-ADForest -ErrorAction Stop
    $RecycleBinFeature = Get-ADOptionalFeature -Filter "Name -eq 'Recycle Bin Feature'" -ErrorAction Stop
    $EnabledFeatures = Get-ADOptionalFeature -Filter "Name -eq 'Recycle Bin Feature'" -Properties EnabledScopes | Select-Object -ExpandProperty EnabledScopes
    
    if ($EnabledFeatures) {
        Write-Host "`nStatus: Compliant. Active Directory Recycle Bin is enabled in the forest '$($Forest.Name)'." -ForegroundColor Green
    } else {
        Write-Host "`nVULNERABLE: Active Directory Recycle Bin is NOT enabled in the forest '$($Forest.Name)'." -ForegroundColor Red
    }
} catch {
    Write-Host "VULNERABLE: Could not query optional features. Error: $($_.Exception.Message)" -ForegroundColor Red
}
```

#### 2. Local Remediation (Enable-ADRecycleBin.ps1)

```powershell
# Enable-ADRecycleBin.ps1
# Description: Enables the Active Directory Recycle Bin optional feature forest-wide.

Import-Module ActiveDirectory

Write-Host "Applying hardening requirement: Enable Active Directory Recycle Bin..." -ForegroundColor Cyan

try {
    $Forest = Get-ADForest -ErrorAction Stop
    $RecycleBinFeature = Get-ADOptionalFeature -Filter "Name -eq 'Recycle Bin Feature'" -ErrorAction Stop
    $EnabledFeatures = Get-ADOptionalFeature -Filter "Name -eq 'Recycle Bin Feature'" -Properties EnabledScopes | Select-Object -ExpandProperty EnabledScopes
    
    if (-not $EnabledFeatures) {
        Write-Host "[+] Enabling Recycle Bin Feature in forest '$($Forest.Name)'..." -ForegroundColor Yellow
        Enable-ADOptionalFeature -Identity $RecycleBinFeature -Scope ForestOrConfigurationSet -Target $Forest.Name -Confirm:$false -ErrorAction Stop
        Write-Host "[+] Active Directory Recycle Bin enabled successfully." -ForegroundColor Green
    } else {
        Write-Host "[+] Active Directory Recycle Bin is already enabled." -ForegroundColor Green
    }
} catch {
    Write-Error "Failed to enable AD Recycle Bin. Error: $($_.Exception.Message)"
}
```

---

## Sources & Compliance References
* **ANSSI AD Hardening Guide**: Section on Active Directory Recycle Bin and backup/restore.
* **Microsoft Best Practices**: Active Directory Recycle Bin Step-by-Step Guide.
