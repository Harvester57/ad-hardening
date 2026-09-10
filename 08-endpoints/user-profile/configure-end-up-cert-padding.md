# [REQ-END-155] User Profile: Authenticode Signature Certificate Padding Check for Endpoints

## Target Scope
* **Applicable Systems**: Tier 2 Client Workstations and Member Servers. *(For Tier 0 Privileged Access Workstations, refer to tightened baseline [REQ-PAW-144](../../07-paws/user-profile/configure-paw-up-cert-padding.md)).*
* **Operating Systems**: Windows 10 Enterprise/Professional (all supported builds), Windows 11 Enterprise/Pro, Windows Server 2016, 2019, 2022, and 2025.

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
Digital signature verification (Authenticode) is the foundational trust boundary used by Windows Defender Application Control (WDAC), AppLocker, Antivirus engines, and the operating system loader to establish software provenance and integrity. A fundamental design loophole in legacy Authenticode validation allows adversaries to tamper with signed binaries without invalidating their digital signature unless strict certificate padding validation is enforced.

### 1. Authenticode Architecture & WIN_CERTIFICATE Internals
When a Portable Executable (PE) binary is digitally signed, the digital signature is stored within the PE file's Attribute Certificate Table, identified by `IMAGE_DIRECTORY_ENTRY_SECURITY` in the optional header:
* The signature blob is encapsulated in a `WIN_CERTIFICATE` structure containing a PKCS #7 signed data packet.
* Under legacy WinTrust specifications, `wintrust.dll` calculates the PE file hash over designated sections (DOS header, PE header, sections, and Authenticode blob), but ignores unverified trailing padding appended to the end of the `WIN_CERTIFICATE` structure.
* **CVE-2013-3900 / MS13-098**: This vulnerability enables adversaries to take a legitimately signed, trusted binary (e.g., a signed Microsoft system executable or certified driver) and append arbitrary malicious payloads, encrypted shellcode, or unpacker stubs to the signature block.
* Because standard `wintrust.dll` verification routines did not enforce strict length matching, the modified executable retained a cryptographically "Valid" Authenticode signature status when examined by the Windows API (`WinVerifyTrust`).

### 2. Threat Vectors & Subverting Application Control
* **Bypassing AppLocker and WDAC Publisher Rules**: Application allowlisting rules that permit binaries signed by trusted publishers (such as Microsoft, Google, or enterprise PKI) are circumvented if adversaries can append malicious logic to a signed executable without breaking its signature.
* **Living-off-the-Land Signed Binaries (LOLBins)**: Threat actors modify legitimate signed management binaries to embed secondary payloads, evading Endpoint Detection and Response (EDR) signature inspections.
* Setting `EnableCertPaddingCheck = 1` in both the native 64-bit and WOW64 32-bit `Wintrust\Config` hives instructs the WinTrust cryptographic subsystem to verify that the size of the certificate block strictly matches the PKCS #7 specification, immediately flagging any binary with extraneous padding as invalid and untrusted.

### 3. MITRE ATT&CK Mapping
* **T1553.002 - Subvert Trust Controls: Code Signing**: Tampering with signed PE binaries or abusing certificate padding to evade signature validation.
* **T1204.002 - User Execution: Malicious File**: Delivering modified signed binaries that exploit trust mechanisms to execute arbitrary code.
* **T1218 - System Binary Proxy Execution**: Utilizing legitimate signed system binaries modified with appended data to proxy malicious execution.

---

## Legacy Impact & Compatibility
* **Legacy Installers and Self-Extracting Archives**: Some older third-party software installers or self-extracting archive tools (created prior to 2014) dynamically appended installation metadata or license payloads to signed setup packages. Such installers will report signature errors (`TRUST_E_NOSIGNATURE` / `0x800B0100` or invalid hash) and fail execution.
* **Modern Enterprise Software**: All modern enterprise software, drivers, and updates comply with strict Authenticode standards and function without issue.
* **Dual-Architecture Enforcement**: Enforcing this control across both native (`HKLM\Software\Microsoft\Cryptography\Wintrust\Config`) and WOW64 (`HKLM\Software\Wow6432Node\...`) paths guarantees that 32-bit legacy runtimes cannot be used as an exploitation escape hatch.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to workstations and member servers (e.g., `GPO_Hardening_Endpoints`).
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
6. Link the GPO to the appropriate Organizational Unit and verify policy enforcement using `gpupdate /force`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to enforce Authenticode certificate padding validation:

[Download Script: Configure-EndAuditCertpadding.ps1](../implementation_scripts/Configure-EndAuditCertpadding.ps1)

```powershell
# Configure-EndAuditCertpadding.ps1
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

[Download Script: Get-EndAuditCertpaddingStatus.ps1](../audit_scripts/Get-EndAuditCertpaddingStatus.ps1)

```powershell
# Get-EndAuditCertpaddingStatus.ps1
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
* **Microsoft Security Advisory**: MS13-098 / CVE-2013-3900 (Vulnerability in Windows WinTrust Could Allow Remote Code Execution)
