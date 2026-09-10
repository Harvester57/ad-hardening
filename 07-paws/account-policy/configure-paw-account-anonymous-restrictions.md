# [REQ-PAW-164] Account Policy: Anonymous Access and Enumeration Restrictions for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) dedicated to Tier 0 directory administration.
* **Operating Systems**: Windows 10 Enterprise (1809 and above), Windows 11 Enterprise (all builds).

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
* **Supported On**: Windows 10 Enterprise / Windows 11 Enterprise
* **Registry Keys & Values**:
  * `HKLM\System\CurrentControlSet\Control\Lsa\RestrictAnonymousSAM` = `1` (REG_DWORD, Disallow anonymous SAM enumeration)
  * `HKLM\System\CurrentControlSet\Control\Lsa\RestrictAnonymous` = `1` (REG_DWORD, Disallow anonymous enumeration of shares and accounts)
  * `HKLM\System\CurrentControlSet\Control\Lsa\Kerberos\Parameters\AllowPKU2U` = `0` (REG_DWORD, Disallow PKU2U peer-to-peer authentication)
  * `HKLM\System\CurrentControlSet\Control\Lsa\ObaseCaseInsensitive` = `1` (REG_DWORD, Enforce case insensitivity for non-Windows subsystems)
* **Vulnerability References**:
  * MITRE ATT&CK: [T1087.001: Local Account Discovery](https://attack.mitre.org/techniques/T1087/001/), [T1087.002: Domain Account Discovery](https://attack.mitre.org/techniques/T1087/002/), [T1135: Network Share Discovery](https://attack.mitre.org/techniques/T1135/), [T1018: Remote System Discovery](https://attack.mitre.org/techniques/T1018/), [T1021.002: Remote Services: SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002/)

---

## Rationale

Unauthenticated network enumeration provides initial access actors with reconnaissance data required to map administrative privileges, local accounts, and shared directory resources:

### Technical Threat Vectors and Defense Mechanics
1. **Null Session SAM & Share Enumeration (`RestrictAnonymousSAM = 1`, `RestrictAnonymous = 1`)**:
   By default or in unhardened legacy environments, Windows SMB implementations allow null session connections (unauthenticated sessions established with username `""` and password `""` via `IPC$`). Through these null sessions, an adversary can query the Security Account Manager Remote Protocol (SAMR, `\pipe\samr`) and Server Service Remote Protocol (SRVSVC, `\pipe\srvsvc`). Using API calls such as `SamrEnumerateUsersInDomain`, `SamrQueryInformationUser`, and `NetShareEnum`, an unauthenticated network observer can extract complete user rosters, security group memberships, and share paths. Setting `RestrictAnonymousSAM = 1` and `RestrictAnonymous = 1` instructs the Local Security Authority (LSA) to reject all unauthenticated SAMR and SRVSVC RPC queries, blinding reconnaissance tools such as `enum4linux`, `nullinux`, and `nmap`.
2. **Anonymous SID/Name Translation Lockdown**:
   Allowing anonymous callers to perform SID-to-name translations permits attackers to probe well-known Relative Identifiers (RIDs)—such as RID 500 (built-in Administrator) or RID 512 (Domain Admins)—to resolve localized administrative account names, even if accounts have been renamed. Explicitly disabling anonymous SID translation stops unauthenticated RID-cycling reconnaissance.
3. **PKU2U Protocol Elimination (`AllowPKU2U = 0`)**:
   Public Key Cryptography Based User-to-User (PKU2U) is an authentication Security Support Provider (SSP) introduced to facilitate peer-to-peer authentication between devices using online consumer Microsoft Accounts (MSAs) without requiring an Active Directory domain controller. On Privileged Access Workstations, which represent the Tier 0 directory management perimeter, peer-to-peer online authentication bypasses Kerberos ticket granting and Active Directory authentication policies. Disabling PKU2U shuts down peer-to-peer shadow authentication channels.
4. **Subsystem Namespace Spoofing Prevention (`ObaseCaseInsensitive = 1`)**:
   The Windows NT Object Manager kernel treats object names (devices, symbolic links, named pipes) as case-insensitive by default. However, POSIX and other non-Windows subsystems support case-sensitive namespace lookup. If case insensitivity is not enforced globally, an attacker could create an object whose name differs only by letter case from a protected system object (for example, creating a malicious named pipe or device symlink), inducing confused deputy vulnerabilities or namespace collisions in system services.
5. **Tier 0 PAW Isolation Posture**:
   PAWs host high-privilege credentials for Enterprise Admins and Domain Admins. Permitting any form of unauthenticated query or non-standard authentication handshake exposes these critical platforms to network-level mapping and exploitation.

---

## Legacy Impact & Compatibility

* **Unauthenticated Network Scanners**: Vulnerability management scanners or network discovery appliances that rely on unauthenticated SMB null sessions to discover local shares and users will fail. All administrative inventory tools must use authenticated domain service accounts or WinRM over TLS.
* **Non-Domain Peer Sharing**: Disabling PKU2U prevents ad-hoc file sharing and remote desktop sessions with machines that authenticate using personal Microsoft Accounts. Tier 0 PAWs must never engage in peer-to-peer resource sharing.
* **Subsystem Applications**: Enforcing case insensitivity has no impact on modern Win32 or .NET applications. Only specialized legacy POSIX-compliant applications expecting case-sensitive object namespaces could experience collision issues, which have no legitimate purpose on administrative workstations.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the PAW GPO linked to the PAW Organizational Unit (e.g., `GPO_Hardening_PAWs`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options`
4. Configure the following policies:
   * **Network access: Do not allow anonymous enumeration of SAM accounts**: Set to `Enabled`
   * **Network access: Do not allow anonymous enumeration of SAM accounts and shares**: Set to `Enabled`
   * **Network access: Allow anonymous SID/Name translation**: Set to `Disabled`
   * **Network security: Allow PKU2U authentication requests to this computer to use online identities**: Set to `Disabled`
   * **System objects: Require case insensitivity for non-Windows subsystems**: Set to `Enabled`
5. Link the GPO to the dedicated PAW OU and force replication across Domain Controllers.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

[Download Script: Configure-PawAccountAnonymousRestrictions.ps1](../implementation_scripts/Configure-PawAccountAnonymousRestrictions.ps1)

```powershell
# Configure-PawAccountAnonymousRestrictions.ps1
# Description: Hardens anonymous access, SAM enumeration, PKU2U, and subsystem object naming on PAWs.

Write-Host "Configuring PAW anonymous access and enumeration restrictions..." -ForegroundColor Cyan

$LsaPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
if (-not (Test-Path -Path $LsaPath)) {
    New-Item -Path $LsaPath -Force | Out-Null
}
Set-ItemProperty -Path $LsaPath -Name "RestrictAnonymousSAM" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $LsaPath -Name "RestrictAnonymous" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $LsaPath -Name "ObaseCaseInsensitive" -Value 1 -Type DWord -Force

$KerbPath = "HKLM:\System\CurrentControlSet\Control\Lsa\Kerberos\Parameters"
if (-not (Test-Path -Path $KerbPath)) {
    New-Item -Path $KerbPath -Force | Out-Null
}
Set-ItemProperty -Path $KerbPath -Name "AllowPKU2U" -Value 0 -Type DWord -Force

Write-Host "Anonymous access and enumeration restrictions applied successfully." -ForegroundColor Green
```

*To audit the hardening status:*

[Download Script: Get-PawAccountAnonymousRestrictionsStatus.ps1](../audit_scripts/Get-PawAccountAnonymousRestrictionsStatus.ps1)

```powershell
# Get-PawAccountAnonymousRestrictionsStatus.ps1
# Description: Audits PAW anonymous enumeration, PKU2U, and subsystem object security configuration.

Write-Host "--- Auditing PAW Anonymous Access and Enumeration Restrictions ---" -ForegroundColor Cyan
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

Verify the applied registry values via command prompt using `reg query`:
```cmd
reg query "HKLM\System\CurrentControlSet\Control\Lsa" /v RestrictAnonymousSAM
reg query "HKLM\System\CurrentControlSet\Control\Lsa" /v RestrictAnonymous
reg query "HKLM\System\CurrentControlSet\Control\Lsa" /v ObaseCaseInsensitive
reg query "HKLM\System\CurrentControlSet\Control\Lsa\Kerberos\Parameters" /v AllowPKU2U
```
Confirm that `RestrictAnonymousSAM`, `RestrictAnonymous`, and `ObaseCaseInsensitive` return `0x1`, and `AllowPKU2U` returns `0x0`.

---

## Sources & Compliance References
* **CIS Microsoft Windows 10 Enterprise Benchmark**: Section 2.3.10.3 (RestrictAnonymousSAM), Section 2.3.10.4 (RestrictAnonymous), Section 2.3.11.3 (AllowPKU2U), Section 2.3.15.1 (ObaseCaseInsensitive)
* **CIS Microsoft Windows 11 Enterprise Benchmark**: Section 2.3.10.3, Section 2.3.10.4, Section 2.3.11.3, Section 2.3.15.1
* **DoD Windows 11 Computer STIG**: Rule SV-220726r879626_rule (RestrictAnonymousSAM), Rule SV-220727r879627_rule (RestrictAnonymous), Rule SV-220732r879632_rule (AllowPKU2U), Rule SV-220738r879638_rule (ObaseCaseInsensitive)
* **ANSSI Active Directory Hardening Guide**: Section 3.4 (PAW Isolation and Reconnaissance Surface Minimization)
* **Microsoft Security Baseline Focus**: Windows Client Security Baseline - Local Policies Security Options
* **Related Controls**: [REQ-END-175: Account Policy: Anonymous Access and Enumeration Restrictions for Endpoints](../../08-endpoints/account-policy/configure-end-account-anonymous-restrictions.md), [REQ-DC-032: Restrict Anonymous Enumeration on Domain Controllers](../../02-domain-controllers/configure-security-options.md)
