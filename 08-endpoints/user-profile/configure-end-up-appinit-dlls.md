# [REQ-END-159] User Profile: Disabling Injection of AppInit DLLs for Endpoints

## Target Scope
* **Applicable Systems**: Tier 2 Client Workstations and Member Servers. *(For Tier 0 Privileged Access Workstations, refer to tightened baseline [REQ-PAW-148](../../07-paws/user-profile/configure-paw-up-appinit-dlls.md)).*
* **Operating Systems**: Windows 10 Enterprise/Professional (all supported builds), Windows 11 Enterprise/Pro, Windows Server 2016, 2019, 2022, and 2025.

---

## Implementation Details
* **Priority**: High
* **GPO Paths / Registry Locations**:
  * **AppInit DLL Loading Behavior**:
    * GPO Path: `Computer Configuration\Administrative Templates\System\Mitigations` (or Group Policy Preferences Registry Policy)
    * Registry Path: `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows`
    * Value Name: `LoadAppInit_DLLs`
    * Value Type: `REG_DWORD`
    * Value Data: `0` (Disabled / Prohibit AppInit DLL injection)
  * **AppInit DLL List Sanitization**:
    * Registry Path: `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows`
    * Value Name: `AppInit_DLLs`
    * Value Type: `REG_SZ`
    * Value Data: `""` (Empty string)
  * **Require Cryptographically Signed AppInit DLLs**:
    * Registry Path: `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows`
    * Value Name: `RequireSignedAppInit_DLLs`
    * Value Type: `REG_DWORD`
    * Value Data: `1` (Enabled / Require digital signature if invoked)

---

## Rationale
AppInit_DLLs is a legacy Windows application infrastructure mechanism dating back to Windows NT. It allows system administrators and software vendors to specify a list of dynamic-link libraries (DLLs) that are automatically loaded into the virtual address space of every user-mode process that links against `User32.dll`. Because nearly all interactive Win32 desktop applications, Windows system binaries, and management utilities load `User32.dll`, this mechanism represents a pervasive, high-risk attack surface for persistence, privilege escalation, and stealthy code injection.

### 1. User32 Architecture & Injection Mechanics
When a process loads `User32.dll`, the library's initialization routine (`DllMain`) reads the registry key `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows`. If `LoadAppInit_DLLs` is set to `1`:
* `User32.dll` invokes `LoadLibrary()` sequentially for each whitespace- or comma-delimited DLL path listed in the `AppInit_DLLs` registry value.
* These libraries execute arbitrary code within the target process's context during initialization, before the application's primary entry point executes.
* If an unprivileged or low-integrity process can modify this registry key (or if an adversary achieves local administrative compromise), they can inject rootkits, credential harvest hooks, or API detours into every subsequent GUI application launched by any user, including elevated administrative sessions.

### 2. Threat Vectors & Exploitation Mechanics
* **Stealthy Persistence**: Adversaries use the AppInit registry key as an autostart execution point (ASEP) that does not show up in conventional Startup folders or standard Run keys.
* **Security Software Blind Spots**: DLLs loaded via AppInit execute in the address space of trusted, signed system binaries (such as `explorer.exe`, `taskmgr.exe`, or `cmd.exe`), complicating process-based anomaly detection.
* **Bypassing AppLocker & Application Control**: Depending on rule definitions, injecting malicious logic into already-allowed processes circumvents path- or publisher-based execution restrictions.
* **Interaction with Secure Boot**: While UEFI Secure Boot automatically disables AppInit DLLs when enabled, relying exclusively on Secure Boot leaves systems vulnerable if Secure Boot is misconfigured, temporarily bypassed, or running in virtualized environments where virtual firmware verification is not enforced. Hardening `LoadAppInit_DLLs = 0` provides defense-in-depth enforcement at the Windows subsystem layer.

### 3. MITRE ATT&CK Mapping
* **T1546.010 - Event Triggered Execution: AppInit DLLs**: Establishing persistence or executing malicious payloads via `LoadAppInit_DLLs`.
* **T1055.001 - Process Injection: Dynamic-link Library Injection**: Forcing target processes to load unauthorized dynamic modules during startup.
* **T1574.002 - Hijack Execution Flow: DLL Side-Loading**: Leveraging system loading sequences to execute malicious code within trusted application contexts.

---

## Legacy Impact & Compatibility
* **Third-Party Application Compatibility**: Legacy screen readers, specialized banking software plugins, and obsolete application performance monitoring (APM) tools occasionally utilized AppInit DLLs for API hooking. Modern enterprise software utilizes Microsoft-supported hooking mechanisms, Detours, or Windows Filtering Platform (WFP).
* **Display and Accessibility Drivers**: Modern accessibility tools and graphics suites conform to Windows 10/11 WHQL driver signing and UI Automation APIs, eliminating reliance on AppInit injection.
* **Auditing Pre-Existing Hooks**: Prior to enforcing `LoadAppInit_DLLs = 0`, inspect `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs` across representative fleet systems to ensure no legitimate, approved business software is broken.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to workstations and member servers (e.g., `GPO_Hardening_Endpoints`).
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
6. Link the GPO to the appropriate Organizational Unit and verify policy enforcement using `gpupdate /force`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to configure the AppInit DLL lockdown registry settings:

[Download Script: Configure-EndAuditAppinitdlls.ps1](../implementation_scripts/Configure-EndAuditAppinitdlls.ps1)

```powershell
# Configure-EndAuditAppinitdlls.ps1
Write-Host "Enforcing System Mitigation control: appinit-dlls..." -ForegroundColor Cyan

# Set Registry value: LoadAppInit_DLLs
if (-not (Test-Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows")) { New-Item -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows" -Force | Out-Null }
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows" -Name "LoadAppInit_DLLs" -Value 0 -Type DWord -Force
Write-Host "    Enforced LoadAppInit_DLLs = 0" -ForegroundColor Green


```

*To audit the hardening status:*

[Download Script: Get-EndAuditAppinitdllsStatus.ps1](../audit_scripts/Get-EndAuditAppinitdllsStatus.ps1)

```powershell
# Get-EndAuditAppinitdllsStatus.ps1
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
* **CIS Benchmark**: CIS Microsoft Windows 10 Enterprise Benchmark: Section 18.9.x; CIS Microsoft Windows 11 Enterprise Benchmark: Section 18.9.x; CIS Windows Server Benchmark: Section 18.9.x
* **DISA STIG**: Windows 10 STIG Rule WN10-CC-000075, Windows 11 STIG Rule WN11-CC-000075, Windows Server 2022 STIG Rule WN22-CC-000075
* **ANSSI Active Directory Hardening Guide**: Recommendation R37 (Securing administrative workstations and disabling legacy DLL injection paths)
* **Microsoft Security Guidance**: Secure Boot and AppInit DLLs (KB2734944)
