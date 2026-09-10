# [REQ-END-040] Disable LxssManager Service (LxssManager)

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers. *(For Tier 0 Privileged Access Workstations, refer to tightened baseline [REQ-PAW-040](../../07-paws/services/disable-lxssmanager.md)).*
* **Operating Systems**: Windows 10 (all supported editions), Windows 11 Enterprise/Pro, Windows Server 2016, 2019, 2022, and 2025.

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\System Services\LxssManager` -> **Disabled**
  * **Registry Path**: `HKLM\SYSTEM\CurrentControlSet\Services\LxssManager`
  * **Value Name**: `Start`
  * **Value Type**: `REG_DWORD`
  * **Value Data**: `4` (Disabled)

---

## Rationale
The Windows Subsystem for Linux (WSL) service (`LxssManager`) coordinates the lifecycle, initialization, and execution of Linux distributions within Windows, managing syscall translation (WSL 1) or lightweight Hyper-V micro-virtual machines (WSL 2).

### 1. Security Evasion and Uninspected Binary Execution
Enabling WSL on general corporate endpoints creates critical blind spots in enterprise endpoint detection and response (EDR):
* **Bypassing Application Control (AppLocker & WDAC)**: Enterprise application whitelisting rules typically monitor and enforce execution boundaries on Windows Portable Executable (PE) binaries (`.exe`, `.dll`, `.msi`) and Windows scripting hosts (PowerShell, WSH). Linux ELF binaries executing within WSL operate in an isolated Linux userland where standard Windows AppLocker rules do not apply. Adversaries leverage WSL to execute uninspected ELF malware, reverse shells, and post-exploitation toolkits (MITRE ATT&CK T1202 - Indirect Command Execution, T1059.004 - Command and Scripting Interpreter: Unix Shell).
* **Cross-Filesystem Access and Data Exfiltration**: By default, WSL mounts the host Windows filesystem under `/mnt/c/` with the security context of the logged-on user. Malicious processes running inside the Linux environment can read sensitive user documents, harvest cached browser tokens, and access SSH/cloud credentials, bypassing host-based Data Loss Prevention (DLP) drivers.
* **Network Bridging and Tunneling**: WSL 2 operates with virtualized NAT and mirrored networking modes. Attackers can execute native Linux network pivoting tools (such as proxychains, SSH reverse proxies, and packet craft engines) directly within the corporate host, masking malicious traffic beneath virtualization network adapters.

### 2. Principle of Least Functionality
In enterprise production environments:
* Standard office workstations and member servers have no legitimate business requirement to run localized Linux container environments or developer virtualization.
* Disabling `LxssManager` ensures that unapproved Linux distributions cannot be spawned, preventing unauthorized execution environments and closing an established evasion vector.

### 3. MITRE ATT&CK Mapping
* **T1202 - Indirect Command Execution**: Using WSL binaries (`wsl.exe`, `bash.exe`) to execute unauthorized payloads outside Windows execution controls.
* **T1059.004 - Command and Scripting Interpreter: Unix Shell**: Executing malicious shell scripts inside unmonitored Linux namespaces.
* **T1005 - Data from Local System**: Accessing Windows host drive mounts (`/mnt/c/`) to harvest sensitive files from Linux processes.

---

## Legacy Impact & Compatibility
* **Standard Business Users**: Disabling `LxssManager` is completely transparent for standard business users, office applications, and enterprise productivity software.
* **Developer Workstations**: If software developers or DevOps engineers require WSL for approved engineering workflows, place those workstations in a specialized Developer Organizational Unit (OU) with an explicit policy exception, combined with Linux EDR agents (such as Microsoft Defender for Endpoint on WSL2) and WDAC rules enforcing WSL distribution signing.
* **System Virtualization**: Standard Hyper-V virtualization and Windows Sandbox can operate independently if specifically enabled, though general workstations should maintain `LxssManager` in a disabled state.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the target endpoints GPO (e.g., `GPO_Hardening_Endpoints`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\System Services`
4. Locate `LxssManager` (`LxssManager`), double-click to define the policy, and select **Disabled**.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

[Download Script: Configure-DisableLxssManager.ps1](../implementation_scripts/Configure-DisableLxssManager.ps1)

```powershell
# Configure-DisableLxssManager.ps1
# Description: Disables the unnecessary LxssManager (LxssManager) service.

Write-Host "Applying hardening requirement: Disable LxssManager service..." -ForegroundColor Cyan

$ServiceName = "LxssManager"
$RegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$($ServiceName)"

$Service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($null -ne $Service) {
    if ($Service.StartType -ne "Disabled") {
        if ($Service.Status -eq "Running") {
            Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue | Out-Null
        }
        Set-Service -Name $ServiceName -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
        Write-Host "[+] Service '$($ServiceName)' stopped and disabled." -ForegroundColor Green
    } else {
        Write-Host "[~] Service '$($ServiceName)' is already disabled." -ForegroundColor Gray
    }
} else {
    Write-Host "[~] Service '$($ServiceName)' is not installed." -ForegroundColor Gray
}

if (Test-Path -Path $RegPath) {
    Set-ItemProperty -Path $RegPath -Name "Start" -Value 4 -Type DWord -ErrorAction SilentlyContinue | Out-Null
    Write-Host "[+] Registry Start value set to 4 (Disabled) for service '$($ServiceName)'." -ForegroundColor Green
}
```

*To verify the startup type of this unnecessary service:*

[Download Script: Get-LxssManagerStatus.ps1](../audit_scripts/Get-LxssManagerStatus.ps1)

```powershell
# Get-LxssManagerStatus.ps1
# Description: Audits the startup configuration of LxssManager (LxssManager) service.

Write-Host "--- Auditing LxssManager (LxssManager) Service ---" -ForegroundColor Cyan

$ServiceName = "LxssManager"
$RegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$($ServiceName)"
$IsVulnerable = $false

if (Test-Path -Path $RegPath) {
    $StartVal = Get-ItemProperty -Path $RegPath -Name "Start" -ErrorAction SilentlyContinue
    if ($null -ne $StartVal) {
        $Start = $StartVal.Start
        if ($Start -eq 4) {
            Write-Host "[+] Service '$($ServiceName)' is secure (Disabled)." -ForegroundColor Green
        } else {
            Write-Host "[!] VULNERABLE: Service '$($ServiceName)' startup type is not Disabled (Start value is $($Start))." -ForegroundColor Red
            $IsVulnerable = $true
        }
    } else {
        Write-Host "[!] VULNERABLE: Service '$($ServiceName)' exists but Start registry value is missing." -ForegroundColor Red
        $IsVulnerable = $true
    }
} else {
    Write-Host "[+] Service '$($ServiceName)' is not installed (Secure)." -ForegroundColor Green
}

if ($IsVulnerable) {
    Write-Host "Audit Result: VULNERABLE" -ForegroundColor Red
    exit 1
} else {
    Write-Host "Audit Result: SECURE" -ForegroundColor Green
    exit 0
}
```

---

## Sources & Compliance References
* **CIS Microsoft Windows Client Benchmark**: Section 5.11 (LxssManager)
* **ANSSI Active Directory Hardening Guide**: Recommendations on host service minimization
* **DoD Windows 11 Computer STIG v2r6**: Unnecessary services restrictions
