# [REQ-PAW-040] Disable LxssManager Service for PAWs (LxssManager)

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration. *(For standard client workstations and member servers, refer to baseline [REQ-END-040](../../08-endpoints/services/disable-lxssmanager.md)).*
* **Operating Systems**: Windows 10 Enterprise (all supported builds) and Windows 11 Enterprise.

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\System Services\LxssManager` -> **Disabled**
  * **Registry Path**: `HKLM\SYSTEM\CurrentControlSet\Services\LxssManager`
  * **Value Name**: `Start`
  * **Value Type**: `REG_DWORD`
  * **Value Data**: `4` (Disabled)

---

## Rationale
The Windows Subsystem for Linux (WSL) service (`LxssManager`) manages the lifecycle, execution, and resource allocation of Linux distributions within Windows, utilizing syscall translation or lightweight Hyper-V micro-virtual machines.

### 1. Inherent Threat to Privileged Access Workstation Isolation
Operating a Linux subsystem on a Tier 0 administrative workstation introduces unacceptable security vulnerabilities:
* **Evasion of Application Control (WDAC & AppLocker)**: PAWs depend on strict application control policies (Windows Defender Application Control and AppLocker) to ensure that only cryptographically signed, vetted administrative binaries can execute. Linux ELF binaries running within WSL bypass standard Windows AppLocker PE-based execution rules. Adversaries or compromised accounts could spawn WSL to execute unmonitored ELF exploit payloads, memory dumpers, or reverse shells (MITRE ATT&CK T1202 - Indirect Command Execution, T1059.004 - Command and Scripting Interpreter: Unix Shell).
* **Host Filesystem Access and Credential Exposure**: WSL automatically mounts the host Windows filesystem under `/mnt/c/`, granting Linux userland processes direct read/write access to host drives, administrative scripts, and local temporary directories. This cross-environment access creates a critical vector for exfiltrating sensitive Active Directory administrative data.
* **Virtual Network Bridging**: WSL 2 introduces virtual Hyper-V network switches and virtual network adapters. This unmonitored networking layer creates opportunities for network evasion, unauthorized packet tunneling, and lateral movement from within the virtualized Linux environment.

### 2. PAW Clean Source and Single-Purpose Architecture
Under Microsoft's PAW security architecture:
* **Single-Purpose Administrative Rigor**: PAWs are dedicated exclusively to directory and identity management (Domain Controllers, PKI, Tier 0 infrastructure). PAWs must never function as software engineering or development workstations.
* **Kernel Attack Surface Reduction**: Permitting guest Linux kernels or complex container namespaces on a Tier 0 host unnecessarily inflates the kernel exploit surface.
* **Disabling `LxssManager`**: Disabling this service ensures that WSL cannot be initialized or executed under any circumstances on administrative workstations, preserving the integrity of the clean source platform.

### 3. MITRE ATT&CK Mapping
* **T1202 - Indirect Command Execution**: Bypassing Windows host execution restrictions using WSL binaries.
* **T1059.004 - Command and Scripting Interpreter: Unix Shell**: Executing malicious shell scripts outside Windows security monitoring.
* **T1005 - Data from Local System**: Accessing Windows host drive mounts to extract sensitive administrative files.

---

## Legacy Impact & Compatibility
* **Tier 0 Administrative Management**: Disabling `LxssManager` has zero impact on Active Directory administration, server management tools (RSAT), PowerShell remoting, or Hyper-V administration.
* **Strict Prohibition on PAWs**: No exceptions should be granted for WSL on Tier 0 PAWs. Administrators requiring Linux administration capabilities must access dedicated, segregated Linux bastion hosts or administrative jump boxes rather than executing Linux userlands locally on Tier 0 hardware.
* **Clean Source Perimeter**: Enforces strict execution containment on the administrative operating system.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the PAW GPO (e.g., `GPO_Hardening_PAW`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\System Services`
4. Locate `LxssManager` (`LxssManager`), double-click to define the policy, and select **Disabled**.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

[Download Script: Configure-DisablePawLxssManager.ps1](../implementation_scripts/Configure-DisablePawLxssManager.ps1)

```powershell
# Configure-DisablePawLxssManager.ps1
# Description: Disables the unnecessary LxssManager (LxssManager) service on the local PAW.

Write-Host "Applying hardening requirement: Disable LxssManager service on PAW..." -ForegroundColor Cyan

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

*To verify the startup type of this unnecessary service on the PAW:*

[Download Script: Get-PawLxssManagerStatus.ps1](../audit_scripts/Get-PawLxssManagerStatus.ps1)

```powershell
# Get-PawLxssManagerStatus.ps1
# Description: Audits the startup configuration of LxssManager (LxssManager) service on the local PAW system.

Write-Host "--- Auditing LxssManager (LxssManager) Service on PAW ---" -ForegroundColor Cyan

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
* **ANSSI Active Directory Hardening Guide**: Recommendations on limiting active background services on sensitive hosts
* **DoD Windows 11 Computer STIG v2r6**: Unnecessary services restrictions
