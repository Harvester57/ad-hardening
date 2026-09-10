# [REQ-END-175] Account Policy: Anonymous Access and Enumeration Restrictions for Endpoints

## Target Scope
* **Applicable Systems**: Tier 2 Client Workstations and Member Servers.
* **Operating Systems**: Windows 10 Enterprise/Professional (1809 and above), Windows 11 Enterprise/Professional (all builds), Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: High
* **Policy Category**: Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
* **Policy Settings**:
  * Network access: Do not allow anonymous enumeration of SAM accounts: `Enabled`
  * Network access: Do not allow anonymous enumeration of SAM accounts and shares: `Enabled`
  * Network access: Allow anonymous SID/Name translation: `Disabled`
  * Network security: Allow PKU2U authentication requests to this computer to use online identities: `Disabled`
  * System objects: Require case insensitivity for non-Windows subsystems: `Enabled`
* **Supported On**: Windows 10 / Windows 11 / Windows Server 2016 and above
* **Registry Keys & Values**:
  * `HKLM\System\CurrentControlSet\Control\Lsa\RestrictAnonymousSAM` = `1` (REG_DWORD, Disallow anonymous SAM enumeration)
  * `HKLM\System\CurrentControlSet\Control\Lsa\RestrictAnonymous` = `1` (REG_DWORD, Disallow anonymous enumeration of shares and accounts)
  * `HKLM\System\CurrentControlSet\Control\Lsa\Kerberos\Parameters\AllowPKU2U` = `0` (REG_DWORD, Disallow PKU2U peer-to-peer authentication)
  * `HKLM\System\CurrentControlSet\Control\Lsa\ObaseCaseInsensitive` = `1` (REG_DWORD, Enforce case insensitivity for non-Windows subsystems)
* **Vulnerability References**:
  * MITRE ATT&CK: [T1087.001: Local Account Discovery](https://attack.mitre.org/techniques/T1087/001/), [T1087.002: Domain Account Discovery](https://attack.mitre.org/techniques/T1087/002/), [T1135: Network Share Discovery](https://attack.mitre.org/techniques/T1135/), [T1018: Remote System Discovery](https://attack.mitre.org/techniques/T1018/), [T1021.002: Remote Services: SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002/)

---

## Rationale

Restricting unauthenticated network reconnaissance protects local SAM databases, user account identifiers, and shared directory paths across enterprise endpoints and member servers:

### Technical Threat Vectors and Defense Mechanics
1. **Null Session Exploitation & SAMR Enumeration (`RestrictAnonymousSAM = 1`, `RestrictAnonymous = 1`)**:
   Standard Windows SMB configurations allow null session connections (unauthenticated binds to `IPC$` with empty credentials). Attackers exploit these connections to query named pipes like `\pipe\samr` (Security Account Manager Remote Protocol) and `\pipe\srvsvc` (Server Service). By invoking RPC functions such as `SamrEnumerateUsersInDomain` and `NetShareEnum`, unauthenticated network actors harvest user lists, group structures, and file shares. Enforcing `RestrictAnonymousSAM = 1` and `RestrictAnonymous = 1` commands LSA to reject anonymous SAM queries and share enumeration, defeating automated network reconnaissance tools (`enum4linux-ng`, `rpcclient`, `CME`).
2. **Anonymous SID/Name Translation Prevention**:
   Permitting anonymous SID lookup enables attackers to perform RID cycling against the endpoint. Attackers probe sequential Relative Identifiers (RIDs 500, 501, 1000+) to map account names and identify built-in administrator accounts that have been renamed for obfuscation. Disabling anonymous SID/name translation completely breaks unauthenticated RID enumeration.
3. **PKU2U Elimination Across Workstations (`AllowPKU2U = 0`)**:
   Public Key Cryptography Based User-to-User (PKU2U) allows peer-to-peer authentication using consumer Microsoft Accounts (MSAs) without contacting an Active Directory domain controller. In an enterprise environment, PKU2U introduces an unmanaged, shadow authentication protocol that circumvents centralized Kerberos policy enforcement and auditing. Disabling PKU2U ensures all endpoint authentication conforms to domain-managed Kerberos and NTLMv2 standards.
4. **Subsystem Namespace Spoofing Mitigation (`ObaseCaseInsensitive = 1`)**:
   The Windows NT kernel Object Manager enforces case-insensitive naming for Win32 objects. However, non-Windows subsystems (e.g., POSIX layers) default to case sensitivity. If disabled, malicious code could create objects that differ only by character case from sensitive system objects (such as device objects or symlinks), causing namespace collisions and confused-deputy authorization bypasses.
5. **Defense-in-Depth Comparison (Endpoint vs PAW)**:
   While Tier 0 PAWs enforce zero-tolerance isolation, Tier 2 client endpoints and member servers must also enforce this baseline to prevent lateral movement following an initial access event on an enterprise workstation.

---

## Legacy Impact & Compatibility

* **Network Inventory Appliances**: Legacy vulnerability scanners or IT asset management tools relying on unauthenticated null sessions will fail to enumerate local users and shares. Management tools must be upgraded or reconfigured to authenticate using dedicated service accounts or WinRM over HTTPS.
* **Peer-to-Peer Sharing**: Disabling PKU2U prevents users from sharing local resources directly using personal Microsoft Account credentials. Enterprise file sharing should occur via approved Active Directory file servers, SharePoint, or OneDrive for Business.
* **Subsystem Applications**: Enforcing case insensitivity has no negative operational impact on standard enterprise desktop and server applications.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the GPO linked to workstations and member servers (e.g., `GPO_Hardening_Endpoints`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options`
4. Configure the following policies:
   * **Network access: Do not allow anonymous enumeration of SAM accounts**: Set to `Enabled`
   * **Network access: Do not allow anonymous enumeration of SAM accounts and shares**: Set to `Enabled`
   * **Network access: Allow anonymous SID/Name translation**: Set to `Disabled`
   * **Network security: Allow PKU2U authentication requests to this computer to use online identities**: Set to `Disabled`
   * **System objects: Require case insensitivity for non-Windows subsystems**: Set to `Enabled`
5. Link the GPO to the appropriate workstation and server Organizational Units (OUs).

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

[Download Script: Configure-EndAccountAnonymousRestrictions.ps1](../implementation_scripts/Configure-EndAccountAnonymousRestrictions.ps1)

```powershell
# Configure-EndAccountAnonymousRestrictions.ps1
# Description: Hardens anonymous access, SAM enumeration, PKU2U, and subsystem object naming on Endpoints.

Write-Host "Configuring Endpoint anonymous access and enumeration restrictions..." -ForegroundColor Cyan

$LsaPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
if (-not (Test-Path -Path $LsaPath)) {
    New-Item -Path $LsaPath -Force | Out-Null
}
Set-ItemProperty -Path $LsaPath -Name "RestrictAnonymousSAM" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $LsaPath -Name "RestrictAnonymous" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $LsaPath -Name "ObaseCaseInsensitive" -Value 1 -Type DWord -Force

$KerbPath = "HKLM:\System\CurrentControlSet\Control\Lsa\Kerberos\Parameters"
if (-not (Test-Path $KerbPath)) {
    New-Item -Path $KerbPath -Force | Out-Null
}
Set-ItemProperty -Path $KerbPath -Name "AllowPKU2U" -Value 0 -Type DWord -Force

Write-Host "Anonymous access and enumeration restrictions applied successfully." -ForegroundColor Green
```

*To audit the hardening status:*

[Download Script: Get-EndAccountAnonymousRestrictionsStatus.ps1](../audit_scripts/Get-EndAccountAnonymousRestrictionsStatus.ps1)

```powershell
# Get-EndAccountAnonymousRestrictionsStatus.ps1
# Description: Audits Endpoint anonymous enumeration, PKU2U, and subsystem object security configuration.

Write-Host "--- Auditing Endpoint Anonymous Access and Enumeration Restrictions ---" -ForegroundColor Cyan
$script:Vulnerable = $false

$LsaPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
$KerbPath = "HKLM:\System\CurrentControlSet\Control\Lsa\Kerberos\Parameters"

function Test-RegVal ($Path, $Name, $Expected) {
    if (-not (Test-Path -Path $Path)) {
        Write-Host "    [!] MISSING KEY: $Path" -ForegroundColor Red
        $script:Vulnerable = $true
        return
    }
    $Prop = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
    if ($null -eq $Prop -or $null -eq $Prop.$Name) {
        Write-Host "    [!] MISSING VALUE: $Name under $Path (Expected: $Expected)" -ForegroundColor Red
        $script:Vulnerable = $true
        return
    }
    $Val = $Prop.$Name
    if ($Val -ne $Expected) {
        Write-Host "    [!] VULNERABLE: $Name under $Path is '$Val' (Expected: $Expected)" -ForegroundColor Red
        $script:Vulnerable = $true
    } else {
        Write-Host "    [+] $($Name): $Val (Secure)" -ForegroundColor Green
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

### Option C: Manual Verification

Verify the applied registry settings using `reg query`:
```cmd
reg query "HKLM\System\CurrentControlSet\Control\Lsa" /v RestrictAnonymousSAM
reg query "HKLM\System\CurrentControlSet\Control\Lsa" /v RestrictAnonymous
reg query "HKLM\System\CurrentControlSet\Control\Lsa" /v ObaseCaseInsensitive
reg query "HKLM\System\CurrentControlSet\Control\Lsa\Kerberos\Parameters" /v AllowPKU2U
```
Confirm that each key exists and the values match: `RestrictAnonymousSAM` = `0x1`, `RestrictAnonymous` = `0x1`, `ObaseCaseInsensitive` = `0x1`, and `AllowPKU2U` = `0x0`.

---

## Sources & Compliance References
* **CIS Microsoft Windows 10 Enterprise Benchmark**: Section 2.3.10.3 (RestrictAnonymousSAM), Section 2.3.10.4 (RestrictAnonymous), Section 2.3.11.3 (AllowPKU2U), Section 2.3.15.1 (ObaseCaseInsensitive)
* **CIS Microsoft Windows 11 Enterprise Benchmark**: Section 2.3.10.3, Section 2.3.10.4, Section 2.3.11.3, Section 2.3.15.1
* **CIS Microsoft Windows Server 2022 Benchmark**: Section 2.3.10.3, Section 2.3.10.4, Section 2.3.11.3, Section 2.3.15.1
* **DoD Windows 11 Computer STIG**: Rule SV-220726r879626_rule (RestrictAnonymousSAM), Rule SV-220727r879627_rule (RestrictAnonymous), Rule SV-220732r879632_rule (AllowPKU2U), Rule SV-220738r879638_rule (ObaseCaseInsensitive)
* **ANSSI Active Directory Hardening Guide**: Section 3.4 (Minimizing Unauthenticated Network Reconnaissance Interfaces)
* **Microsoft Security Baseline Focus**: Windows Client Security Baseline - Local Policies Security Options
* **Related Controls**: [REQ-PAW-164: Account Policy: Anonymous Access and Enumeration Restrictions for PAWs](../../07-paws/account-policy/configure-paw-account-anonymous-restrictions.md), [REQ-DC-032: Restrict Anonymous Enumeration on Domain Controllers](../../02-domain-controllers/configure-security-options.md)
