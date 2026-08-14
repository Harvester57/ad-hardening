# [REQ-END-175] Account Policy: Anonymous Access and Enumeration Restrictions for Endpoints

## Target Scope
* **Applicable Systems**: Tier 2 Client Workstations, Member Servers, Domain Controllers
* **Operating Systems**: Windows 10/11 Enterprise/Professional, Windows Server 2016 (and above)

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options`
  * **Registry Locations**:
    * `HKLM\System\CurrentControlSet\Control\Lsa\RestrictAnonymousSAM` = `1` (REG_DWORD, Do not allow anonymous enumeration of SAM accounts)
    * `HKLM\System\CurrentControlSet\Control\Lsa\RestrictAnonymous` = `1` (REG_DWORD, Do not allow anonymous enumeration of shares)
    * `HKLM\System\CurrentControlSet\Control\Lsa\Kerberos\Parameters\AllowPKU2U` = `0` (REG_DWORD, Disallow PKU2U authentication requests)
    * `HKLM\System\CurrentControlSet\Control\Lsa\ObaseCaseInsensitive` = `1` (REG_DWORD, Require case insensitivity for non-Windows subsystems)

---

## Rationale
Restricting unauthenticated reconnaissance and non-standard authentication endpoints shields local system objects and user databases:
* **Anonymous SAM & Share Enumeration (`RestrictAnonymousSAM`, `RestrictAnonymous`)**: Prevents unauthenticated network callers from querying local user accounts, group memberships, or shared directory paths via null sessions.
* **Disallow PKU2U (`AllowPKU2U`)**: PKU2U allows peer-to-peer authentication using online Microsoft accounts. Disabling PKU2U blocks peer authentication bypasses across enterprise endpoints.
* **Subsystem Case Insensitivity (`ObaseCaseInsensitive`)**: Enforces consistent case insensitivity for non-Windows subsystems, mitigating object namespace collision exploits.

---

## Legacy Impact & Compatibility
* **Anonymous Queries**: Legacy applications attempting to query SAM or share lists anonymously will receive Access Denied.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the Endpoints GPO (e.g., `GPO_Hardening_Workstations`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options`
4. Configure the policies:
   * **Network access: Do not allow anonymous enumeration of SAM accounts and shares**: `Enabled`
   * **Network access: Allow anonymous SID/Name translation**: `Disabled`
   * **Network Security: Allow PKU2U authentication requests to this computer to use online identities**: `Disabled`
   * **System objects: Require case insensitivity for non-Windows subsystems**: `Enabled`

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

[Download Script: Configure-EndAccountAnonymousRestrictions.ps1](../implementation_scripts/Configure-EndAccountAnonymousRestrictions.ps1)

```powershell
# Configure-EndAccountAnonymousRestrictions.ps1
Write-Host "Configuring Endpoint anonymous access and enumeration restrictions..." -ForegroundColor Cyan

$LsaPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
if (-not (Test-Path $LsaPath)) { New-Item -Path $LsaPath -Force | Out-Null }
Set-ItemProperty -Path $LsaPath -Name "RestrictAnonymousSAM" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $LsaPath -Name "RestrictAnonymous" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $LsaPath -Name "ObaseCaseInsensitive" -Value 1 -Type DWord -Force

$KerbPath = "HKLM:\System\CurrentControlSet\Control\Lsa\Kerberos\Parameters"
if (-not (Test-Path $KerbPath)) { New-Item -Path $KerbPath -Force | Out-Null }
Set-ItemProperty -Path $KerbPath -Name "AllowPKU2U" -Value 0 -Type DWord -Force

Write-Host "Anonymous access and enumeration restrictions applied." -ForegroundColor Green
```

*To audit the hardening status:*

[Download Script: Get-EndAccountAnonymousRestrictionsStatus.ps1](../audit_scripts/Get-EndAccountAnonymousRestrictionsStatus.ps1)

```powershell
# Get-EndAccountAnonymousRestrictionsStatus.ps1
Write-Host "--- Auditing Endpoint Anonymous Access and Enumeration Restrictions ---" -ForegroundColor Cyan
$script:Vulnerable = $false

$LsaPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
$KerbPath = "HKLM:\System\CurrentControlSet\Control\Lsa\Kerberos\Parameters"

function Test-RegVal ($Path, $Name, $Expected) {
    $Val = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name
    if ($Val -ne $Expected) {
        Write-Host "    [!] VULNERABLE: $Name under $Path is '$Val' (Expected: $Expected)" -ForegroundColor Red
        $script:Vulnerable = $true
    } else {
        Write-Host "    [+] $($Name): $Val" -ForegroundColor Green
    }
}

Test-RegVal $LsaPath "RestrictAnonymousSAM" 1
Test-RegVal $LsaPath "RestrictAnonymous" 1
Test-RegVal $LsaPath "ObaseCaseInsensitive" 1
Test-RegVal $KerbPath "AllowPKU2U" 0

if ($script:Vulnerable) {
    Write-Output "Non-Compliant"
    exit 1
} else {
    Write-Output "Compliant"
    exit 0
}
```

---

## Sources & Compliance References
* **CIS Microsoft Windows 10/11 Benchmark**: Section 2.3.10.3 (RestrictAnonymousSAM), Section 2.3.11.3 (AllowPKU2U), Section 2.3.15.1 (ObaseCaseInsensitive)
* **ANSSI AD Hardening Guide**: Recommendations on restricting anonymous enumeration and RPC interfaces
* **DoD Windows 11 Computer STIG v2r6**: Anonymous SAM enumeration restrictions
