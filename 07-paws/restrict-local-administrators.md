# [REQ-PAW-003] Restrict Local Administrators Group for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration.
* **Operating Systems**: Windows 10 Enterprise (1607+) and Windows 11 Enterprise.

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**: Computer Configuration\Policies\Windows Settings\Security Settings\Restricted Groups

---

## Rationale
Privileged Access Workstations (PAWs) represent Tier 0 administrative assets. Any user or group that has local administrative rights on a PAW can bypass operating system security boundaries, disable system protections, capture keystrokes, or extract cached credentials.

Restricting local Administrators group membership ensures that:
1. **Administrative Rights Restriction**: Standard domain users and lower-tiered administrators (e.g., workstation support admins) are strictly prevented from executing code in an elevated context on the PAW.
2. **Tier Separation**: Administrative credentials from lower security tiers cannot compromise the PAW. Only dedicated Tier 0 administrators are allowed local administrative access.
3. **Authorized Control**: Membership is strictly controlled and reset periodically via Group Policy (Restricted Groups), preventing persistent privilege creep.

---

## Legacy Impact & Compatibility
* **Daily Work Limitation**: Lower-tier support personnel cannot log on to or troubleshoot the PAW.
* **Dedicated Administrative Accounts**: Administrators must authenticate using their dedicated Tier 0 administrative account (e.g., `a0-admin`). Standard accounts are blocked from gaining administrative access.
* **LAPS Integration**: The local built-in Administrator account (RID 500) should be managed via Windows LAPS to ensure password rotation and secure retrieval.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

Deploy Restricted Groups via GPO to enforce local administrators group memberships:
1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the GPO linked to the PAWs Organizational Unit (OU) (e.g., `GPO_Hardening_PAW`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Restricted Groups`
4. Right-click **Restricted Groups** and select **Add Group**.
5. Type `Administrators` (or click Browse to find the local group).
6. Under **Members of this group**, define the allowed members:
   * `Administrator` (the built-in local administrator account)
   * `DomainName\Tier0-Admins` (dedicated Tier 0 administrative group)
   * *Do NOT include any standard domain users or lower-tier administrative groups.*
7. Link the GPO to the PAWs Organizational Unit (OU).

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following scripts locally to audit and remediate unauthorized administrative accounts in the local Administrators group.

[Download Script: Clean-PawLocalAdministrators.ps1](implementation_scripts/Clean-PawLocalAdministrators.ps1)

```powershell
# Clean-PawLocalAdministrators.ps1
# Description: Removes unauthorized accounts from the local Administrators group on PAWs.

Write-Host "--- Restricting Local Administrators Group on PAW ---" -ForegroundColor Cyan

# Define the list of authorized members
# Built-in Administrator and Tier 0 admin groups
$AuthorizedMembers = @("Administrator", "Tier0-Admins")

$LocalAdmins = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue

if ($LocalAdmins) {
    foreach ($Member in $LocalAdmins) {
        $Match = $false
        foreach ($Auth in $AuthorizedMembers) {
            if ($Member.Name -eq $Auth -or $Member.Name -like "*\$Auth" -or $Member.Name -eq "$env:COMPUTERNAME\$Auth") {
                $Match = $true
                break
            }
        }
        
        if (-not $Match) {
            Write-Host "[-] Removing unauthorized member from Administrators: $($Member.Name) (Source: $($Member.PrincipalSource))" -ForegroundColor Yellow
            try {
                Remove-LocalGroupMember -Group "Administrators" -Member $Member.Name -ErrorAction Stop
                Write-Host "    Successfully removed: $($Member.Name)" -ForegroundColor Green
            } catch {
                Write-Error "    Failed to remove: $($Member.Name). Error: $($_.Exception.Message)"
            }
        } else {
            Write-Host "[+] Member authorized: $($Member.Name)" -ForegroundColor Green
        }
    }
} else {
    Write-Error "Could not retrieve members of local Administrators group."
}
```

*To audit local Administrators group memberships on the PAW:*

[Download Script: Test-PawLocalAdministrators.ps1](audit_scripts/Test-PawLocalAdministrators.ps1)

```powershell
# Test-PawLocalAdministrators.ps1
# Description: Audits local Administrators group memberships to ensure only authorized Tier 0 accounts are present.

Write-Host "--- Auditing PAW Local Administrators Group ---" -ForegroundColor Cyan

# Define the authorized domain/local patterns
$AuthorizedMembers = @("Administrator", "Tier0-Admins")

$LocalAdmins = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue

if ($LocalAdmins) {
    Write-Host "[*] Current members of local Administrators group:" -ForegroundColor Yellow
    foreach ($Member in $LocalAdmins) {
        $Match = $false
        foreach ($Auth in $AuthorizedMembers) {
            if ($Member.Name -eq $Auth -or $Member.Name -like "*\$Auth" -or $Member.Name -eq "$env:COMPUTERNAME\$Auth") {
                $Match = $true
                break
            }
        }
        
        if (-not $Match) {
            Write-Host "    - VULNERABLE: Unauthorized account '$($Member.Name)' (Source: $($Member.PrincipalSource)) has administrative access." -ForegroundColor Red
        } else {
            Write-Host "    - Member: $($Member.Name) | Source: $($Member.PrincipalSource) | Class: $($Member.ObjectClass) (Authorized)" -ForegroundColor Green
        }
    }
} else {
    Write-Error "Failed to retrieve local Administrators group members."
}
```

---

## Sources & Compliance References
* **ANSSI AD Hardening Guide**: Recommendations on administrative isolation and local admin restriction.
* **CIS Microsoft Windows 10/11 Benchmark**: Section 5.5 (Ensure only authorized accounts are members of the Administrators group)
* **Microsoft Security Baselines**: Restricted Groups settings for high-security domain systems.
