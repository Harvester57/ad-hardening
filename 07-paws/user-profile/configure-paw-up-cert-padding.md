# [REQ-PAW-144] User Profile: Authenticode Signature Certificate Padding Check for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 Active Directory and identity infrastructure administration. *(For Tier 2 Client Workstations and Member Servers, refer to baseline [REQ-END-155](../../08-endpoints/user-profile/configure-end-up-cert-padding.md)).*
* **Operating Systems**: Windows 10 Enterprise (version 1809 and above), Windows 11 Enterprise.

---

## Implementation Details
* **Priority**: High
* **GPO Paths / Registry Locations**:
  * **Authenticode Signature Padding Verification (64-bit)**:
    * GPO Path: `Computer Configuration\Administrative Templates\System\Mitigations` (or Group Policy Preferences Registry Policy)
    * Registry Path: `HKLM\Software\Microsoft\Cryptography\Wintrust\Config`
    * Value Name: `EnableCertPaddingCheck`
    * Value Type: `REG_DWORD`
    * Value Data: `1` (Enabled / Enforce strict Authenticode signature padding check)
  * **Authenticode Signature Padding Verification (32-bit WOW64)**:
    * Registry Path: `HKLM\Software\Wow6432Node\Microsoft\Cryptography\Wintrust\Config`
    * Value Name: `EnableCertPaddingCheck`
    * Value Type: `REG_DWORD`
    * Value Data: `1` (Enabled / Enforce strict Authenticode signature padding check for 32-bit processes)

---

## Rationale
On Privileged Access Workstations (PAWs), Windows Defender Application Control (WDAC) and AppLocker enforce rigorous publisher signature rules to guarantee that only cryptographically verified, Microsoft-signed, or enterprise-approved binaries can execute. A vulnerability in legacy Authenticode processing (CVE-2013-3900) allows adversaries to append unauthorized code or secondary payloads to signed PE files without breaking the signature, creating a critical evasion pathway on administrative systems.

### 1. Authenticode Architecture & WIN_CERTIFICATE Internals
Portable Executable (PE) digital signatures reside in the Attribute Certificate Table defined by `IMAGE_DIRECTORY_ENTRY_SECURITY`:
* The digital signature is stored in a `WIN_CERTIFICATE` structure containing a PKCS #7 signed message.
* In default legacy WinTrust processing, `wintrust.dll` ignores data appended past the defined length of the ASN.1 signature structure.
* **CVE-2013-3900**: An attacker targeting a PAW can obtain a legitimate signed binary (such as an administrative tool, signed debugger, or Microsoft helper binary), append a malicious payload to the trailing padding of the certificate table, and distribute the binary.
* Without `EnableCertPaddingCheck = 1`, `WinVerifyTrust` reports the manipulated binary as genuine and valid, allowing it to bypass strict WDAC publisher rules and AppLocker policies designed to protect Tier 0 workstations.

### 2. Tier 0 Threat Vectors & PAW Isolation
* **Subverting WDAC Publisher Allowlisting**: PAWs mandate WDAC policies that permit only verified code. Padding attacks permit attackers to execute arbitrary shellcode or DLLs masquerading as legitimate Microsoft administrative software.
* **Dual-Bitness Defense-in-Depth**: Hardening both the 64-bit and 32-bit (WOW64) branches ensures that malicious utilities running under 32-bit subsystem emulation cannot bypass WinTrust integrity checks.
* Setting `EnableCertPaddingCheck = 1` forces `wintrust.dll` to perform strict size verification against the PKCS #7 content length, instantly rejecting any binary with extraneous padding.

### 3. MITRE ATT&CK Mapping
* **T1553.002 - Subvert Trust Controls: Code Signing**: Tampering with signed administrative binaries to bypass WDAC or AppLocker validation.
* **T1204.002 - User Execution: Malicious File**: Executing weaponized signed binaries on administrative consoles.
* **T1218 - System Binary Proxy Execution**: Proxying execution through signed system binaries modified with appended data.

---

## Legacy Impact & Compatibility
* **PAW Dedicated Role**: PAW systems execute only modern, validated administrative tooling. Legacy installers and obsolete unpackers that utilize non-standard padding are strictly barred from PAWs by design.
* **Administrative Tooling**: RSAT, Windows Admin Center, PowerShell, and system utilities conform strictly to standard Authenticode specifications and run without disruption.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to Tier 0 Privileged Access Workstations (e.g., `GPO_Hardening_PAW`).
3. Navigate to: `Computer Configuration \ Preferences \ Windows Settings \ Registry`
4. Right-click **Registry** -> **New** -> **Registry Item** (Native 64-bit) and configure:
   * **Action**: `Update`
   * **Hive**: `HKEY_LOCAL_MACHINE`
   * **Key Path**: `Software\Microsoft\Cryptography\Wintrust\Config`
   * **Value Name**: `EnableCertPaddingCheck`
   * **Value Type**: `REG_DWORD`
   * **Value Data**: `1`
5. Right-click **Registry** -> **New** -> **Registry Item** (WOW64 32-bit) and configure:
   * **Action**: `Update`
   * **Hive**: `HKEY_LOCAL_MACHINE`
   * **Key Path**: `Software\Wow6432Node\Microsoft\Cryptography\Wintrust\Config`
   * **Value Name**: `EnableCertPaddingCheck`
   * **Value Type**: `REG_DWORD`
   * **Value Data**: `1`
6. Link the GPO to the dedicated PAW Organizational Unit and enforce replication using `gpupdate /force`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to enforce Authenticode certificate padding validation on the PAW console:

[Download Script: Configure-PawAuditCertpadding.ps1](../implementation_scripts/Configure-PawAuditCertpadding.ps1)

```powershell
# Configure-PawAuditCertpadding.ps1
Write-Host "Enforcing System Mitigation control: cert-padding..." -ForegroundColor Cyan

# Set Registry value: EnableCertPaddingCheck
if (-not (Test-Path "HKLM:\Software\Microsoft\Cryptography\Wintrust\Config")) { New-Item -Path "HKLM:\Software\Microsoft\Cryptography\Wintrust\Config" -Force | Out-Null }
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Cryptography\Wintrust\Config" -Name "EnableCertPaddingCheck" -Value 1 -Type DWord -Force
Write-Host "    Enforced EnableCertPaddingCheck = 1" -ForegroundColor Green

# Set Registry value: EnableCertPaddingCheck
if (-not (Test-Path "HKLM:\Software\Wow6432Node\Microsoft\Cryptography\Wintrust\Config")) { New-Item -Path "HKLM:\Software\Wow6432Node\Microsoft\Cryptography\Wintrust\Config" -Force | Out-Null }
Set-ItemProperty -Path "HKLM:\Software\Wow6432Node\Microsoft\Cryptography\Wintrust\Config" -Name "EnableCertPaddingCheck" -Value 1 -Type DWord -Force
Write-Host "    Enforced EnableCertPaddingCheck = 1" -ForegroundColor Green


```

*To audit the hardening status:*

[Download Script: Get-PawAuditCertpaddingStatus.ps1](../audit_scripts/Get-PawAuditCertpaddingStatus.ps1)

```powershell
# Get-PawAuditCertpaddingStatus.ps1
$script:Vulnerable = $false

# Audit Registry value: EnableCertPaddingCheck
$RegVal = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Cryptography\Wintrust\Config" -Name "EnableCertPaddingCheck" -ErrorAction SilentlyContinue
if (-not $RegVal -or $RegVal.EnableCertPaddingCheck -ne 1) {
    $script:Vulnerable = $true
}

# Audit Registry value: EnableCertPaddingCheck
$RegVal = Get-ItemProperty -Path "HKLM:\Software\Wow6432Node\Microsoft\Cryptography\Wintrust\Config" -Name "EnableCertPaddingCheck" -ErrorAction SilentlyContinue
if (-not $RegVal -or $RegVal.EnableCertPaddingCheck -ne 1) {
    $script:Vulnerable = $true
}

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
* **CIS Benchmark**: CIS Microsoft Windows 10 Enterprise Benchmark: Section 18.9.x; CIS Microsoft Windows 11 Enterprise Benchmark: Section 18.9.x
* **DISA STIG**: Windows 10 STIG Rule WN10-CC-000100, Windows 11 STIG Rule WN11-CC-000100
* **ANSSI Active Directory Hardening Guide**: Recommendation R37 (Securing code execution and cryptographic verification baselines)
* **Microsoft Privileged Access Guidance**: Securing Privileged Access: System-Level Hardening and Memory Protections
