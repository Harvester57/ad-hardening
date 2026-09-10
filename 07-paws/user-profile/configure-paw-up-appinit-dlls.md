# [REQ-PAW-148] User Profile: Disabling Injection of AppInit DLLs for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 Active Directory and infrastructure administration. *(For Tier 2 Client Workstations and Member Servers, refer to baseline [REQ-END-159](../../08-endpoints/user-profile/configure-end-up-appinit-dlls.md)).*
* **Operating Systems**: Windows 10 Enterprise (version 1809 and above), Windows 11 Enterprise.

---

## Implementation Details
* **Priority**: High
* **GPO Paths / Registry Locations**:
  * **AppInit DLL Loading Behavior**:
    * GPO Path: `Computer Configuration\Administrative Templates\System\Mitigations` (or Group Policy Preferences Registry Policy)
    * Registry Path: `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows`
    * Value Name: `LoadAppInit_DLLs`
    * Value Type: `REG_DWORD`
    * Value Data: `0` (Disabled / Strictly prohibit AppInit DLL injection)
  * **AppInit DLL List Sanitization**:
    * Registry Path: `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows`
    * Value Name: `AppInit_DLLs`
    * Value Type: `REG_SZ`
    * Value Data: `""` (Empty string)
  * **Require Cryptographically Signed AppInit DLLs**:
    * Registry Path: `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows`
    * Value Name: `RequireSignedAppInit_DLLs`
    * Value Type: `REG_DWORD`
    * Value Data: `1` (Enabled / Require WHQL / Microsoft digital signature if invoked)

---

## Rationale
Privileged Access Workstations (PAWs) are dedicated exclusively to administrative tasks against Tier 0 Active Directory Domain Controllers, Certificate Authorities, and identity infrastructure. In a PAW environment, the presence of legacy process injection pathways creates an unacceptable threat surface that could allow an attacker or malicious user-mode software to hook administrative tools (e.g., PowerShell, RSAT, MMC, `dsa.msc`, `ntdsutil`) and compromise Tier 0 credentials.

### 1. User32 Architecture & Injection Mechanics
When any Win32 graphical application or utility initializes `User32.dll`, the subsystem queries `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows`:
* If `LoadAppInit_DLLs` is enabled (`1`), `User32.dll` sequentially loads each DLL declared in `AppInit_DLLs` into the virtual address space of the process using `LoadLibrary()`.
* On administrative consoles, sensitive utilities and management scripts necessarily link against `User32.dll` for UI rendering, dialog displays, and credential prompt controls.
* If `LoadAppInit_DLLs` is active, any compromised driver, unverified management agent, or low-privilege persistence mechanism can automatically achieve code execution inside administrative sessions, intercepting plaintext credentials and Kerberos TGTs before they are encrypted.

### 2. Tier 0 Threat Vectors & PAW Isolation
* **Credential Scraping from Tier 0 Management Tools**: Threat actors targeting Domain Admins can inject unbacked or side-loaded DLLs into RSAT consoles to siphon domain administrative credentials during interactive logon or delegation.
* **Subverting Application Allowlisting (AppLocker / WDAC)**: On PAWs enforced with strict WDAC (Windows Defender Application Control) policies, AppInit DLLs historically represented a mechanism for sideloading unvetted code into signed host binaries if signature enforcement was not comprehensively applied.
* **Hardening Redundancy Beyond UEFI Secure Boot**: While UEFI Secure Boot automatically disables unsigned AppInit DLLs, dedicated Tier 0 systems must maintain defense-in-depth at the registry layer. Setting `LoadAppInit_DLLs = 0` guarantees complete suppression even during recovery operations, maintenance boot modes, or hypervisor migration scenarios.

### 3. MITRE ATT&CK Mapping
* **T1546.010 - Event Triggered Execution: AppInit DLLs**: Establishing persistence or executing malicious payloads via `LoadAppInit_DLLs`.
* **T1055.001 - Process Injection: Dynamic-link Library Injection**: Forcing administrative processes to load unauthorized dynamic modules during startup.
* **T1003.001 - OS Credential Dumping: LSASS Memory**: Intercepting administrative authentication material from processes operating in high-integrity sessions.

---

## Legacy Impact & Compatibility
* **PAW Dedicated Role**: PAWs do not run general enterprise desktop software, third-party accessibility tools, or legacy enterprise resource planning (ERP) suites. Therefore, disabling AppInit DLLs causes zero operational disruption.
* **Administrative Tooling**: Native Windows administrative tools (RSAT, Windows Admin Center, PowerShell 5.1/7.x) do not rely on AppInit DLLs and operate cleanly under this policy.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to Tier 0 Privileged Access Workstations (e.g., `GPO_Hardening_PAW`).
3. Navigate to: `Computer Configuration \ Preferences \ Windows Settings \ Registry`
4. Right-click **Registry** -> **New** -> **Registry Item** and configure:
   * **Action**: `Update`
   * **Hive**: `HKEY_LOCAL_MACHINE`
   * **Key Path**: `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows`
   * **Value Name**: `LoadAppInit_DLLs`
   * **Value Type**: `REG_DWORD`
   * **Value Data**: `0`
5. Create a secondary Registry Item to clear the DLL list:
   * **Action**: `Update`
   * **Hive**: `HKEY_LOCAL_MACHINE`
   * **Key Path**: `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows`
   * **Value Name**: `AppInit_DLLs`
   * **Value Type**: `REG_SZ`
   * **Value Data**: `""`
6. Link the GPO to the dedicated PAW Organizational Unit and enforce replication using `gpupdate /force`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to configure the AppInit DLL lockdown on the PAW console:

[Download Script: Configure-PawAuditAppinitdlls.ps1](../implementation_scripts/Configure-PawAuditAppinitdlls.ps1)

```powershell
# Configure-PawAuditAppinitdlls.ps1
Write-Host "Enforcing System Mitigation control: appinit-dlls..." -ForegroundColor Cyan

# Set Registry value: LoadAppInit_DLLs
if (-not (Test-Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows")) { New-Item -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows" -Force | Out-Null }
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows" -Name "LoadAppInit_DLLs" -Value 0 -Type DWord -Force
Write-Host "    Enforced LoadAppInit_DLLs = 0" -ForegroundColor Green


```

*To audit the hardening status:*

[Download Script: Get-PawAuditAppinitdllsStatus.ps1](../audit_scripts/Get-PawAuditAppinitdllsStatus.ps1)

```powershell
# Get-PawAuditAppinitdllsStatus.ps1
$script:Vulnerable = $false

# Audit Registry value: LoadAppInit_DLLs
$RegVal = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows" -Name "LoadAppInit_DLLs" -ErrorAction SilentlyContinue
if (-not $RegVal -or $RegVal.LoadAppInit_DLLs -ne 0) {
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
* **DISA STIG**: Windows 10 STIG Rule WN10-CC-000075, Windows 11 STIG Rule WN11-CC-000075
* **ANSSI Active Directory Hardening Guide**: Recommendation R37 (Securing administrative workstations and disabling legacy DLL injection paths)
* **Microsoft Privileged Access Guidance**: Securing Privileged Access: System-Level Hardening and Memory Protections
