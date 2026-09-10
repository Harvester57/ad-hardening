# [REQ-END-169] Account Policy: NTLM and LAN Manager Authentication Security for Endpoints

## Target Scope
* **Applicable Systems**: Tier 2 Client Workstations and Member Servers.
* **Operating Systems**: Windows 10 Enterprise/Professional (1809 and above), Windows 11 Enterprise/Professional (all builds), Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: High
* **Policy Category**: Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
* **Policy Settings**:
  * Network security: LAN Manager authentication level: `Send NTLMv2 response only. Refuse LM & NTLM` (value `5`)
  * Network security: Minimum session security for NTLM SSP based (including secure RPC) clients: `Require NTLMv2 session security, Require 128-bit encryption` (value `537395200`)
  * Network security: Minimum session security for NTLM SSP based (including secure RPC) servers: `Require NTLMv2 session security, Require 128-bit encryption` (value `537395200`)
  * Network security: Allow LocalSystem NULL session fallback: `Disabled` (value `0`)
* **Supported On**: Windows 10 / Windows 11 / Windows Server 2016 and above
* **Registry Keys & Values**:
  * `HKLM\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel` = `5` (REG_DWORD, Send NTLMv2 only, refuse LM & NTLMv1)
  * `HKLM\System\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinClientSec` = `537395200` (REG_DWORD, 0x20080000: NTLMv2 session security + 128-bit encryption)
  * `HKLM\System\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinServerSec` = `537395200` (REG_DWORD, 0x20080000: NTLMv2 session security + 128-bit encryption)
  * `HKLM\System\CurrentControlSet\Control\Lsa\MSV1_0\allownullsessionfallback` = `0` (REG_DWORD, Prohibits LocalSystem NULL session fallback)
* **Vulnerability References**:
  * MITRE ATT&CK: [T1557.001: Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and Relay](https://attack.mitre.org/techniques/T1557/001/), [T1187: Forced Authentication](https://attack.mitre.org/techniques/T1187/), [T1110: Brute Force](https://attack.mitre.org/techniques/T1110/)

---

## Rationale

Legacy authentication protocols such as LAN Manager (LM) and NTLMv1 represent major vectors for credential interception, offline password recovery, and adversary-in-the-middle relay attacks across corporate networks. Hardening NTLM authentication parameters across endpoints enforces modern cryptographic session controls:

### Technical Threat Vectors and Defense Mechanics
1. **Defeating NTLMv1 Offline Des Cracking (`LmCompatibilityLevel = 5`)**:
   NTLMv1 challenge-response exchanges use 56-bit DES keys generated from the user's NT hash. Online cracking services and modern FPGA/GPU arrays can crack any intercepted NTLMv1 response in less than 24 hours, yielding the complete plaintext NT hash. Setting `LmCompatibilityLevel = 5` enforces that client systems only send NTLMv2 responses, and server services explicitly refuse inbound LM and NTLMv1 negotiations. NTLMv2 utilizes HMAC-MD5 with client and server nonces, variable-length timestamped client challenge blobs, preventing precomputed rainbow table attacks.
2. **Mandating 128-Bit Session Security (`537395200` = `0x20080000`)**:
   When applications use NTLM SSP for authenticated RPC or SMB sessions, session keys establish encryption and integrity signing. The decimal value `537395200` (`0x20080000`) enables:
   * Bit `0x00080000`: Require NTLMv2 session security.
   * Bit `0x20000000`: Require 128-bit encryption.
   This prohibits negotiation of 40-bit or 56-bit export ciphers, shielding in-flight network session tokens from passive eavesdropping and man-in-the-middle tampering.
3. **Closing LocalSystem NULL Session Fallback (`allownullsessionfallback = 0`)**:
   In unhardened environments, when a process executing under `NT AUTHORITY\SYSTEM` attempts NTLM authentication to a remote resource and negotiation fails, Windows can fall back to an unauthenticated NULL session. Threat actors utilizing coerce-and-relay attack techniques (e.g., PetitPotam, PrinterBug) exploit this behavior to interact with RPC endpoints anonymously. Setting `allownullsessionfallback = 0` forces failed authentications to terminate cleanly rather than downgrading to an unauthenticated session.
4. **Endpoint Posture**:
   Across Tier 2 enterprise workstations and member servers, enforcing Level 5 and 128-bit session security raises the authentication security baseline without disrupting normal domain operations, as all supported Windows platforms have natively supported NTLMv2 since Windows NT 4.0 SP4.

---

## Legacy Impact & Compatibility

* **Legacy Appliances & Multi-Function Printers**: Obsolete network attached storage (NAS) devices, ancient multi-function printers (MFPs), or third-party legacy appliances that lack NTLMv2 support will fail authentication with `STATUS_LOGON_FAILURE`. These systems must be upgraded to support NTLMv2 or migrated to Kerberos authentication.
* **Kerberos Unaffected**: Active Directory domain members authenticate using Kerberos by default. NTLM is only invoked when target systems are referenced by IP address or belong to untrusted forests.
* **Pre-Deployment Auditing**: Organizations can enable NTLM auditing via the `Microsoft-Windows-NTLM/Operational` event log to identify any residual applications relying on legacy NTLM variants prior to enterprise-wide enforcement.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the GPO linked to workstations and member servers (e.g., `GPO_Hardening_Endpoints`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options`
4. Configure the following policies:
   * **Network security: LAN Manager authentication level**: Set to `Send NTLMv2 response only. Refuse LM & NTLM` (value `5`)
   * **Network security: Minimum session security for NTLM SSP based (including secure RPC) clients**: Check both `Require NTLMv2 session security` and `Require 128-bit encryption` (value `537395200`)
   * **Network security: Minimum session security for NTLM SSP based (including secure RPC) servers**: Check both `Require NTLMv2 session security` and `Require 128-bit encryption` (value `537395200`)
   * **Network security: Allow LocalSystem NULL session fallback**: Set to `Disabled` (value `0`)
5. Link the GPO to the appropriate workstation and member server Organizational Units.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

[Download Script: Configure-EndAccountNtlmSecurity.ps1](../implementation_scripts/Configure-EndAccountNtlmSecurity.ps1)

```powershell
# Configure-EndAccountNtlmSecurity.ps1
# Description: Enforces NTLMv2-only authentication, 128-bit session security, and blocks NULL session fallback on Endpoints.

Write-Host "Configuring Endpoint NTLM and LAN Manager authentication security..." -ForegroundColor Cyan

$LsaPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
if (-not (Test-Path $LsaPath)) {
    New-Item -Path $LsaPath -Force | Out-Null
}
Set-ItemProperty -Path $LsaPath -Name "LmCompatibilityLevel" -Value 5 -Type DWord -Force

$MsvPath = "HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0"
if (-not (Test-Path $MsvPath)) {
    New-Item -Path $MsvPath -Force | Out-Null
}
Set-ItemProperty -Path $MsvPath -Name "NTLMMinClientSec" -Value 537395200 -Type DWord -Force
Set-ItemProperty -Path $MsvPath -Name "NTLMMinServerSec" -Value 537395200 -Type DWord -Force
Set-ItemProperty -Path $MsvPath -Name "allownullsessionfallback" -Value 0 -Type DWord -Force

Write-Host "NTLM and LAN Manager authentication security applied successfully." -ForegroundColor Green
```

*To audit the hardening status:*

[Download Script: Get-EndAccountNtlmSecurityStatus.ps1](../audit_scripts/Get-EndAccountNtlmSecurityStatus.ps1)

```powershell
# Get-EndAccountNtlmSecurityStatus.ps1
# Description: Audits NTLM authentication levels, session security, and NULL session fallback on Endpoints.

Write-Host "--- Auditing Endpoint NTLM and LAN Manager Security ---" -ForegroundColor Cyan
$script:Vulnerable = $false

$LsaPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
$MsvPath = "HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0"

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

Test-RegVal $LsaPath "LmCompatibilityLevel" 5
Test-RegVal $MsvPath "NTLMMinClientSec" 537395200
Test-RegVal $MsvPath "NTLMMinServerSec" 537395200
Test-RegVal $MsvPath "allownullsessionfallback" 0

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

Verify the applied NTLM settings using command prompt queries:
```cmd
reg query "HKLM\System\CurrentControlSet\Control\Lsa" /v LmCompatibilityLevel
reg query "HKLM\System\CurrentControlSet\Control\Lsa\MSV1_0" /v NTLMMinClientSec
reg query "HKLM\System\CurrentControlSet\Control\Lsa\MSV1_0" /v NTLMMinServerSec
reg query "HKLM\System\CurrentControlSet\Control\Lsa\MSV1_0" /v allownullsessionfallback
```
Confirm that `LmCompatibilityLevel` is `0x5`, `NTLMMinClientSec` and `NTLMMinServerSec` are `0x20080000` (Decimal `537395200`), and `allownullsessionfallback` is `0x0`.

---

## Sources & Compliance References
* **CIS Microsoft Windows 10 Enterprise Benchmark**: Section 2.3.11.2 (LmCompatibilityLevel = 5), Section 2.3.11.7 (NTLMMinClientSec = 537395200), Section 2.3.11.8 (NTLMMinServerSec = 537395200), Section 2.3.11.10 (allownullsessionfallback = 0)
* **CIS Microsoft Windows 11 Enterprise Benchmark**: Section 2.3.11.2, Section 2.3.11.7, Section 2.3.11.8, Section 2.3.11.10
* **CIS Microsoft Windows Server 2022 Benchmark**: Section 2.3.11.2, Section 2.3.11.7, Section 2.3.11.8, Section 2.3.11.10
* **DoD Windows 11 Computer STIG**: Rule SV-220731r879631_rule (NTLM authentication level), Rule SV-220736r879636_rule (NTLM minimum session security for clients), Rule SV-220737r879637_rule (NTLM minimum session security for servers)
* **ANSSI Active Directory Hardening Guide**: Recommendations on NTLM deprecation, forced authentication defenses, and NTLMv2 enforcement
* **Microsoft Security Baseline Focus**: Windows Client Security Baseline - Local Policies Security Options
* **Related Controls**: [REQ-PAW-158: Account Policy: NTLM and LAN Manager Authentication Security for PAWs](../../07-paws/account-policy/configure-paw-account-ntlm-security.md), [REQ-DC-032: Restrict NTLM on Domain Controllers](../../02-domain-controllers/configure-security-options.md)
