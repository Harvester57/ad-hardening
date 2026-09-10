# [REQ-PAW-158] Account Policy: NTLM and LAN Manager Authentication Security for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) dedicated to Tier 0 directory administration.
* **Operating Systems**: Windows 10 Enterprise (1809 and above), Windows 11 Enterprise (all builds).

---

## Implementation Details
* **Priority**: High
* **Policy Category**: Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
* **Policy Settings**:
  * Network security: LAN Manager authentication level: `Send NTLMv2 response only. Refuse LM & NTLM` (value `5`)
  * Network security: Minimum session security for NTLM SSP based (including secure RPC) clients: `Require NTLMv2 session security, Require 128-bit encryption` (value `537395200`)
  * Network security: Minimum session security for NTLM SSP based (including secure RPC) servers: `Require NTLMv2 session security, Require 128-bit encryption` (value `537395200`)
  * Network security: Allow LocalSystem NULL session fallback: `Disabled` (value `0`)
* **Supported On**: Windows 10 Enterprise / Windows 11 Enterprise
* **Registry Keys & Values**:
  * `HKLM\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel` = `5` (REG_DWORD, Send NTLMv2 only, refuse LM & NTLMv1)
  * `HKLM\System\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinClientSec` = `537395200` (REG_DWORD, 0x20080000: NTLMv2 session security + 128-bit encryption)
  * `HKLM\System\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinServerSec` = `537395200` (REG_DWORD, 0x20080000: NTLMv2 session security + 128-bit encryption)
  * `HKLM\System\CurrentControlSet\Control\Lsa\MSV1_0\allownullsessionfallback` = `0` (REG_DWORD, Prohibits LocalSystem NULL session fallback)
* **Vulnerability References**:
  * MITRE ATT&CK: [T1557.001: Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and Relay](https://attack.mitre.org/techniques/T1557/001/), [T1187: Forced Authentication](https://attack.mitre.org/techniques/T1187/), [T1110: Brute Force](https://attack.mitre.org/techniques/T1110/)

---

## Rationale

Legacy LAN Manager (LM) and NT LAN Manager version 1 (NTLMv1) authentication protocols are critically vulnerable to cryptographic recovery, offline dictionary cracking, and man-in-the-middle relaying. On Tier 0 Privileged Access Workstations, legacy authentication must be purged and session security fortified:

### Technical Threat Vectors and Defense Mechanics
1. **NTLMv1 Cryptographic Insecurity & Des Infeasibility**:
   NTLMv1 encrypts an 8-byte challenge using the user's 16-byte NT password hash divided into three 7-byte DES keys (with null padding on the last key). Because of the weak 56-bit DES key space and static challenge mechanics, an attacker intercepting an NTLMv1 handshake over the network can retrieve the underlying plaintext NT hash within 24 hours using online rainbow table lookup services (such as Crack.sh) with 100% mathematical certainty. Setting `LmCompatibilityLevel = 5` commands the workstation to strictly transmit NTLMv2 responses and explicitly refuse all inbound LM and NTLMv1 challenges.
2. **NTLMv2 Challenge-Response Mechanics**:
   NTLMv2 replaces weak DES encryption with HMAC-MD5, incorporating a 64-bit client nonce (`ClientChallenge`), a timestamp, and domain information. This construction renders precomputed rainbow table lookups ineffective and protects against straightforward challenge replay.
3. **128-Bit Session Security (`NTLMMinClientSec` / `NTLMMinServerSec` = `537395200`)**:
   The value `537395200` (`0x20080000`) activates two essential security flags:
   * Bit `0x00080000`: Mandates NTLMv2 session security (deriving session keys using HMAC-MD5 over the challenge and nonces).
   * Bit `0x20000000`: Requires full 128-bit encryption for session keys.
   This prevents downgrade to 40-bit or 56-bit export-grade cipher suites, ensuring that any RPC or SMB communication that utilizes NTLM SSP is protected by robust encryption and integrity signing.
4. **Prohibiting LocalSystem NULL Session Fallback (`allownullsessionfallback = 0`)**:
   When services executing under the `NT AUTHORITY\SYSTEM` machine context attempt outbound NTLM authentication to a remote server, negotiation failure can cause Windows to fall back to an unauthenticated NULL session. Threat actors exploiting coercion primitives (such as PetitPotam, ShadowCoerce, or PrinterBug) take advantage of this behavior to interact with RPC interfaces without valid credentials. Setting `allownullsessionfallback = 0` blocks this fallback, forcing connections to fail rather than degrade into an anonymous session.
5. **Tier 0 PAW Isolation Posture**:
   PAWs represent the administrative crown jewels. While the long-term objective for Tier 0 is complete elimination of NTLM in favor of pure Kerberos, enforcing Level 5 and 128-bit session security ensures that any remaining legacy NTLM negotiations cannot be downgraded or captured via legacy protocols.

---

## Legacy Impact & Compatibility

* **Legacy Non-NTLMv2 Systems**: Legacy operating systems, outdated NAS appliances, or embedded printer management utilities that only support LM or NTLMv1 will be unable to authenticate. In modern enterprise environments, Tier 0 PAWs must never communicate with or manage such obsolete assets.
* **Kerberos Preference**: Kerberos remains the default authentication protocol for Active Directory domain members. This setting only affects scenarios where NTLM is negotiated as a fallback (such as IP-address-based connections).
* **Auditing and Verification**: Prior to broad enforcement, administrators can monitor the `Microsoft-Windows-NTLM/Operational` event log (Event IDs 8001, 8002, 8003, 8004) to identify any applications on the network still utilizing legacy NTLM variants.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the PAW GPO linked to the PAW Organizational Unit (e.g., `GPO_Hardening_PAWs`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options`
4. Configure the following policies:
   * **Network security: LAN Manager authentication level**: Set to `Send NTLMv2 response only. Refuse LM & NTLM` (value `5`)
   * **Network security: Minimum session security for NTLM SSP based (including secure RPC) clients**: Check both `Require NTLMv2 session security` and `Require 128-bit encryption` (value `537395200`)
   * **Network security: Minimum session security for NTLM SSP based (including secure RPC) servers**: Check both `Require NTLMv2 session security` and `Require 128-bit encryption` (value `537395200`)
   * **Network security: Allow LocalSystem NULL session fallback**: Set to `Disabled` (value `0`)
5. Link the GPO to the dedicated PAW OU and force update via `gpupdate /force`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

[Download Script: Configure-PawAccountNtlmSecurity.ps1](../implementation_scripts/Configure-PawAccountNtlmSecurity.ps1)

```powershell
# Configure-PawAccountNtlmSecurity.ps1
# Description: Enforces NTLMv2-only authentication, 128-bit session security, and blocks NULL session fallback on PAWs.

Write-Host "Configuring PAW NTLM and LAN Manager authentication security..." -ForegroundColor Cyan

$LsaPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
if (-not (Test-Path -Path $LsaPath)) {
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

[Download Script: Get-PawAccountNtlmSecurityStatus.ps1](../audit_scripts/Get-PawAccountNtlmSecurityStatus.ps1)

```powershell
# Get-PawAccountNtlmSecurityStatus.ps1
# Description: Audits NTLM authentication levels, session security, and NULL session fallback on PAWs.

Write-Host "--- Auditing PAW NTLM and LAN Manager Security ---" -ForegroundColor Cyan
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
* **DoD Windows 11 Computer STIG**: Rule SV-220731r879631_rule (NTLM authentication level), Rule SV-220736r879636_rule (NTLM minimum session security for clients), Rule SV-220737r879637_rule (NTLM minimum session security for servers)
* **ANSSI Active Directory Hardening Guide**: Section 3.4 (NTLM Deprecation and NTLMv2 Enforcement)
* **Microsoft Security Baseline Focus**: Windows Client Security Baseline - Local Policies Security Options
* **Related Controls**: [REQ-END-169: Account Policy: NTLM and LAN Manager Authentication Security for Endpoints](../../08-endpoints/account-policy/configure-end-account-ntlm-security.md), [REQ-DC-032: Restrict NTLM on Domain Controllers](../../02-domain-controllers/configure-security-options.md)
