# [REQ-END-046] Disable Special Administration Console Helper Service (sacsvr)

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers. *(For Tier 0 Privileged Access Workstations, refer to tightened baseline [REQ-PAW-046](../../07-paws/services/disable-sacsvr.md)).*
* **Operating Systems**: Windows 10 (all supported editions), Windows 11 Enterprise/Pro, Windows Server 2016, 2019, 2022, and 2025.

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\System Services\Special Administration Console Helper` -> **Disabled**
  * **Registry Path**: `HKLM\SYSTEM\CurrentControlSet\Services\sacsvr`
  * **Value Name**: `Start`
  * **Value Type**: `REG_DWORD`
  * **Value Data**: `4` (Disabled)

---

## Rationale
The Special Administration Console (SAC) Helper service (`sacsvr`) supports Emergency Management Services (EMS), an out-of-band management architecture developed for headless Windows Server hardware to allow remote diagnostic console access over physical or virtual serial (COM) ports.

### 1. Inapplicability to Client Endpoints and Local Attack Surface
Maintaining an out-of-band serial console helper service on client endpoints presents distinct security and architectural liabilities:
* **Elevated Local RPC Subsystem**: The `sacsvr` service executes under the `NT AUTHORITY\SYSTEM` context, hosting local Inter-Process Communication (IPC) mechanisms and RPC endpoints to bridge kernel-mode EMS drivers with userland administration tools. Running unnecessary privileged services on endpoints expands the local attack surface available for local privilege escalation (LPE) exploits (MITRE ATT&CK T1068 - Exploitation for Privilege Escalation).
* **Absence of Serial Console Infrastructure**: Modern client laptops, desktops, and standard member servers are not connected to serial console terminal servers or out-of-band RS-232 serial networks. Leaving serial console services active provides zero administrative utility on physical or virtual client machines.
* **Kernel Debugging Interfaces**: EMS and SAC integrate directly with low-level kernel debugging and emergency recovery interfaces. Permitting serial console handlers on general endpoints exposes debug-level functionality that should be restricted to isolated server environments.

### 2. Principle of Least Functionality
In enterprise Active Directory environments:
* Workstations must execute only the minimal software footprint necessary for business productivity and standard domain management.
* Disabling `sacsvr` eliminates an unnecessary `NT AUTHORITY\SYSTEM` background daemon and closes local RPC interfaces associated with serial console redirection.

### 3. MITRE ATT&CK Mapping
* **T1068 - Exploitation for Privilege Escalation**: Exploitation of elevated background services running with SYSTEM privileges.
* **T1059 - Command and Scripting Interpreter**: Abuse of alternative administrative command execution conduits.

---

## Legacy Impact & Compatibility
* **Standard Client Management**: Disabling `sacsvr` has zero impact on interactive graphical logons, Remote Desktop (RDP), PowerShell Remoting, WinRM, or Windows Admin Center.
* **Serial Hardware Devices**: Peripheral serial devices (such as USB-to-serial adapters, laboratory instruments, or barcode scanners) use independent COM port driver stacks and are not affected by disabling `sacsvr`.
* **Headless Server Environments**: Only specialized server racks in data centers intentionally configured with serial terminal concentrators require EMS/SAC. Standard corporate workstations and member servers must have this service disabled.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the target endpoints GPO (e.g., `GPO_Hardening_Endpoints`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\System Services`
4. Locate `Special Administration Console Helper` (`sacsvr`), double-click to define the policy, and select **Disabled**.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

[Download Script: Configure-Disablesacsvr.ps1](../implementation_scripts/Configure-Disablesacsvr.ps1)

```powershell
# Configure-Disablesacsvr.ps1
# Description: Disables the unnecessary Special Administration Console Helper (sacsvr) service.

Write-Host "Applying hardening requirement: Disable Special Administration Console Helper service..." -ForegroundColor Cyan

$ServiceName = "sacsvr"
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

[Download Script: Get-sacsvrStatus.ps1](../audit_scripts/Get-sacsvrStatus.ps1)

```powershell
# Get-sacsvrStatus.ps1
# Description: Audits the startup configuration of Special Administration Console Helper (sacsvr) service.

Write-Host "--- Auditing Special Administration Console Helper (sacsvr) Service ---" -ForegroundColor Cyan

$ServiceName = "sacsvr"
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
* **CIS Microsoft Windows Client Benchmark**: Section 5.31 (sacsvr)
* **ANSSI Active Directory Hardening Guide**: Recommendations on host service minimization
* **DoD Windows 11 Computer STIG v2r6**: Unnecessary services restrictions
