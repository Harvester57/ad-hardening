# Hardening Requirement: Enforce Accidental Deletion Protection on Organizational Units

## Target Scope
* **Applicable Systems**: Domain Controllers
* **Operating Systems**: Windows Server 2016 and above

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**: Active Directory Object Access Control Lists (`ProtectedFromAccidentalDeletion` attribute)

---

## Rationale
Organizational Units (OUs) act as the logical containers for structuring users, groups, and computers in Active Directory, and are the targets for linking Group Policy Objects (GPOs).

Enforcing the accidental deletion protection property provides the following security and availability benefits:
1. **Administrative Safeguard**: Drag-and-drop mistakes or batch scripting errors can lead to the deletion of an entire OU hierarchy, causing severe outages and loss of access controls. This feature places a "Deny" Access Control Entry (ACE) for the "Everyone" group on the "Delete" and "Delete Subtree" permissions of the object.
2. **Operational Continuity**: While it does not prevent a malicious administrator from intentionally disabling the setting and deleting the OU, it forces a deliberate, two-step verification process before any destructive actions can be performed.

---

## Legacy Impact & Compatibility
* **Administrative Operations**: When moving an OU, or renaming/deleting it during structural reorganizations, administrators must manually uncheck the protection box (or disable the property via PowerShell) before performing the action.
* **Scripted Creation**: Any custom PowerShell scripts used to provision new OUs should explicitly set the `-ProtectedFromAccidentalDeletion $true` parameter during creation to ensure consistent compliance.

---

## Implementation Steps

### Option A: Active Directory Users and Computers (Preferred)

1. Log on to a management workstation or Domain Controller with **Domain Admins** or **Account Operators** credentials.
2. Open **Active Directory Users and Computers** (`dsa.msc`).
3. In the top menu, click **View** and ensure that **Advanced Features** is checked. This is required to expose the Object tab in properties.
4. Locate the target Organizational Unit, right-click it, and select **Properties**.
5. Navigate to the **Object** tab.
6. Check the box for **Protect object from accidental deletion**.
7. Click **Apply** and **OK**.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following scripts to audit and configure the setting domain-wide.

#### 1. Local Audit (Audit-OUAccidentalDeletion.ps1)

```powershell
# Audit-OUAccidentalDeletion.ps1
# Description: Audits all OUs to find any without accidental deletion protection.

Import-Module ActiveDirectory

Write-Host "--- Auditing OU Accidental Deletion Protection ---" -ForegroundColor Cyan

try {
    $UnprotectedOUs = Get-ADOrganizationalUnit -Filter "ProtectedFromAccidentalDeletion -eq '$false'" -ErrorAction Stop
    
    if ($UnprotectedOUs) {
        Write-Host "`nVULNERABLE: Found $($UnprotectedOUs.Count) Organizational Unit(s) without accidental deletion protection:" -ForegroundColor Red
        foreach ($ou in $UnprotectedOUs) {
            Write-Host "    - OU: $($ou.Name) | DN: $($ou.DistinguishedName)" -ForegroundColor White
        }
    } else {
        Write-Host "`nStatus: Compliant. All Organizational Units are protected from accidental deletion." -ForegroundColor Green
    }
} catch {
    Write-Host "VULNERABLE: Could not audit OUs. Error: $($_.Exception.Message)" -ForegroundColor Red
}
```

#### 2. Local Remediation (Enforce-OUAccidentalDeletion.ps1)

```powershell
# Enforce-OUAccidentalDeletion.ps1
# Description: Enables accidental deletion protection on all OUs in the domain.

Import-Module ActiveDirectory

Write-Host "Applying hardening requirement: Enforce OU Accidental Deletion Protection..." -ForegroundColor Cyan

try {
    $UnprotectedOUs = Get-ADOrganizationalUnit -Filter "ProtectedFromAccidentalDeletion -eq '$false'" -ErrorAction Stop
    
    if ($UnprotectedOUs) {
        Write-Host "[+] Found $($UnprotectedOUs.Count) OUs requiring protection." -ForegroundColor Yellow
        foreach ($ou in $UnprotectedOUs) {
            Set-ADOrganizationalUnit -Identity $ou.DistinguishedName -ProtectedFromAccidentalDeletion $true -ErrorAction Stop
            Write-Host "    Protected OU: $($ou.Name)" -ForegroundColor Green
        }
        Write-Host "[+] All Organizational Units are now protected." -ForegroundColor Green
    } else {
        Write-Host "[+] No unprotected OUs found." -ForegroundColor Green
    }
} catch {
    Write-Error "Failed to enable protection on OUs. Error: $($_.Exception.Message)"
}
```

---

## Sources & Compliance References
* **Microsoft Best Practices**: Protecting Organizational Units from Accidental Deletion.
* **ANSSI AD Hardening Guide**: Operational integrity and directory maintenance recommendations.
