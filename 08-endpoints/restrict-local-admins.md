# [REQ-END-006] Restrict Local Administrators Group

## Target Scope
* **Applicable Systems**: Tier 2 client workstations.
* **Operating Systems**: Windows 10 (and above) Enterprise/Professional.

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **GPO Path**: Computer Configuration\Policies\Windows Settings\Security Settings\Restricted Groups
  * **Registry Location**: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
    * `LocalAccountTokenFilterPolicy` = `0` (REG_DWORD, Disabled)

---

## Rationale
Local administrator rights on workstations are a significant source of operational vulnerability. If standard end-users run as local administrators:
1. **Malware Propagation**: Malware executed by the user runs in an administrative context, allowing it to bypass local firewalls, alter registry hives, disable security controls (like Windows Defender), and persist across reboots.
2. **Credential Harvesting**: Compromised local admin accounts allow attackers to execute memory-dumping tools (e.g., Mimikatz) to harvest stored domain credentials of other users who have logged on to that machine.
3. **Software Control Bypass**: Users can install arbitrary, unapproved software, introducing license compliance risks and unmonitored security vulnerabilities.

Securing the local Administrators group ensures only local security accounts (like the local `Administrator` managed by LAPS) or dedicated workstation support accounts are members. The default `Domain Users` or standard domain accounts must never be allowed local administrative rights.

---

## Legacy Impact & Compatibility
* **User Restrictions**: Users cannot install software, update system drivers, or modify local network configurations. Support staff must assist users with system modifications or use automated software distribution channels.
* **Legacy Apps**: Applications that require local administrator privileges to write data directly to the `%ProgramFiles%` directory or local registry keys will fail. These applications must be reconfigured to write to user-profile locations (e.g., `%APPDATA%`) or run under service account privileges.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

Enforce local Administrators group membership and restrict remote execution via local accounts (UAC remote restrictions):
1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Create or edit a GPO linked to the workstations OU (e.g., `GPO_Hardening_Workstations`).
3. **Configure Restricted Groups**:
   * Navigate to: `Computer Configuration\Policies\Windows Settings\Security Settings\Restricted Groups`
   * Right-click **Restricted Groups** and select **Add Group**.
   * Type `Administrators` (or click Browse to find the local group).
   * Under **Members of this group**, define the allowed members:
     * `Administrator` (the built-in local administrator account)
     * `DomainName\Workstation-Support-Admins` (dedicated Tier 2 support team group, if used)
     * *Leave out `Domain Users` or any other general domain accounts.*
   * Applying this GPO will overwrite the membership of the local Administrators group, immediately removing any account not explicitly listed.
4. **Configure Local Account Token Filter Policy**:
   * Navigate to: `Computer Configuration\Preferences\Windows Settings\Registry`
   * Right-click **Registry** and select **New** -> **Registry Item**.
   * Set **Action**: `Update`
   * Set **Hive**: `HKEY_LOCAL_MACHINE`
   * Set **Key Path**: `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`
   * Set **Value name**: `LocalAccountTokenFilterPolicy`
   * Set **Value type**: `REG_DWORD`
   * Set **Value data**: `0`

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following scripts locally to audit and remediate unauthorized administrative accounts in the local Administrators group and enforce local account remote token restrictions.

[Download Script: Clean-LocalAdministrators.ps1](implementation_scripts/Clean-LocalAdministrators.ps1)

```powershell
# Clean-LocalAdministrators.ps1
# Removes unauthorized domain or local accounts from the local Administrators group and disables local account remote token filtering bypass.

Write-Host "--- Restricting Local Administrators Group ---" -ForegroundColor Cyan

# Define the list of authorized members
# The built-in Administrator account (RID 500) and authorized domain support groups.
$AuthorizedMembers = @("Administrator", "Workstation-Support-Admins")

$LocalAdmins = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue

if ($LocalAdmins) {
    foreach ($Member in $LocalAdmins) {
        # Check if the member is not in the authorized list
        $Match = $false
        foreach ($Auth in $AuthorizedMembers) {
            # Check for exact matches or matches against SAM / SID formats
            if ($Member.Name -eq $Auth -or $Member.Name -like "*\$Auth" -or $Member.Name -eq "$env:COMPUTERNAME\$Auth") {
                $Match = $true
                break
            }
        }
        
        if (-not $Match) {
            Write-Host "[-] Removing unauthorized member: $($Member.Name) (Source: $($Member.PrincipalSource))" -ForegroundColor Yellow
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

# Enforce LocalAccountTokenFilterPolicy = 0
$RegistryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$ValueName = "LocalAccountTokenFilterPolicy"

try {
    if (-not (Test-Path $RegistryPath)) {
        New-Item -Path $RegistryPath -Force | Out-Null
    }
    Set-ItemProperty -Path $RegistryPath -Name $ValueName -Value 0 -Type DWord -Force | Out-Null
    Write-Host "[+] LocalAccountTokenFilterPolicy configured to 0." -ForegroundColor Green
} catch {
    Write-Error "Failed to configure LocalAccountTokenFilterPolicy. Error: $($_.Exception.Message)"
}
```

*To audit local Administrators group memberships and UAC token filtering policy:*
[Download Script: Test-LocalAdministrators.ps1](audit_scripts/Test-LocalAdministrators.ps1)

```powershell
# Test-LocalAdministrators.ps1
# Audits membership of the local Administrators group and checks local account remote token filtering bypass policy.

Write-Host "--- Auditing Local Administrators Group ---" -ForegroundColor Cyan

$LocalAdmins = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue

if ($LocalAdmins) {
    Write-Host "[*] Current members of local Administrators group:" -ForegroundColor Yellow
    foreach ($Member in $LocalAdmins) {
        # Flag any domain user accounts that might have been added to administrators group
        $StatusColor = "Green"
        if ($Member.PrincipalSource -eq "ActiveDirectory" -and $Member.Name -notmatch "Workstation-Support-Admins") {
            $StatusColor = "Red"
            Write-Host "    - VULNERABLE: Domain Account '$($Member.Name)' has local admin rights." -ForegroundColor $StatusColor
        } else {
            Write-Host "    - Member: $($Member.Name) | Source: $($Member.PrincipalSource) | Class: $($Member.ObjectClass)" -ForegroundColor $StatusColor
        }
    }
} else {
    Write-Error "Failed to retrieve local Administrators group members."
}

# Audit LocalAccountTokenFilterPolicy
$RegistryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$ValueName = "LocalAccountTokenFilterPolicy"

if (Test-Path $RegistryPath) {
    $Val = (Get-ItemProperty -Path $RegistryPath -Name $ValueName -ErrorAction SilentlyContinue).$ValueName
    if ($Val -eq 0) {
        Write-Host "[+] LocalAccountTokenFilterPolicy is configured correctly (0)." -ForegroundColor Green
    } elseif ($null -eq $Val) {
        Write-Host "[-] LocalAccountTokenFilterPolicy is not explicitly set (Expected: 0)." -ForegroundColor Red
    } else {
        Write-Host "[-] LocalAccountTokenFilterPolicy is vulnerable: $Val (Expected: 0)." -ForegroundColor Red
    }
} else {
    Write-Host "[-] LocalAccountTokenFilterPolicy is not configured (Expected: 0)." -ForegroundColor Red
}
```

---

## 🔗 Sources & Compliance References
* **CIS Microsoft Windows 10 Benchmark**: Section 5.5 (Ensure only authorized accounts are members of the Administrators group)
* **ANSSI AD Hardening Guide**: Recommendations regarding local administration restriction and tiering boundaries.
