# [REQ-PAW-046] Disable Special Administration Console Helper Service for PAWs (sacsvr)

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration. *(For standard client workstations and member servers, refer to baseline [REQ-END-046](../../08-endpoints/services/disable-sacsvr.md)).*
* **Operating Systems**: Windows 10 Enterprise (all supported builds) and Windows 11 Enterprise.

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
The Special Administration Console (SAC) Helper service (`sacsvr`) facilitates Emergency Management Services (EMS), an out-of-band administrative console subsystem engineered for headless enterprise server hardware to enable text-based diagnostic access over physical or virtual serial (COM) ports.

### 1. Inapplicability to Privileged Access Workstations
Operating out-of-band serial management components on Tier 0 administrative workstations introduces unneeded security exposures:
* **Elevated Privileges and Local Attack Surface**: The `sacsvr` daemon executes in the context of `NT AUTHORITY\SYSTEM`, registering local RPC endpoints and inter-process communication handlers that bridge kernel-mode emergency services with userland utilities. On a Tier 0 PAW, background daemons executing with SYSTEM privileges represent high-value targets for local privilege escalation (LPE) and memory tampering exploits (MITRE ATT&CK T1068 - Exploitation for Privilege Escalation).
* **Zero Architectural Role on PAWs**: PAWs are dedicated, interactive client endpoints equipped with secure local displays and peripheral controls. PAWs are never deployed as headless appliances connected to data center serial terminal servers.
* **Kernel Debugging Interfaces**: EMS integrates directly with low-level Windows kernel debugging and emergency recovery interfaces. Permitting emergency console helper daemons to execute on a PAW unnecessarily exposes low-level OS interfaces.

### 2. PAW Clean Source and Process Minimization
Under the clean source principle and Microsoft PAW guidelines:
* **Minimalist Host Architecture**: Tier 0 administrative workstations must eliminate every non-essential background service. Reducing the number of running processes directly reduces the surface available for credential harvesting and process hollowing.
* **Modern Administration Demarcation**: Tier 0 directory administrators manage domain controllers and member servers exclusively through authenticated, encrypted remote protocols (PowerShell Remoting, WinRM, HTTPS, Kerberos-authenticated RPC). PAWs have no operational requirement for serial console redirection.
* **Deallocation of Resources**: Disabling `sacsvr` guarantees that no serial console helper threads or IPC endpoints are active on the administrative host.

### 3. MITRE ATT&CK Mapping
* **T1068 - Exploitation for Privilege Escalation**: Exploitation of elevated helper services running with SYSTEM privileges.
* **T1059 - Command and Scripting Interpreter**: Abuse of alternative command execution interfaces on administrative hosts.

---

## Legacy Impact & Compatibility
* **Tier 0 Administrative Management**: Disabling `sacsvr` has zero impact on Active Directory administration, server management tools (RSAT), PowerShell remoting, or Hyper-V administration.
* **Local Display and Console**: Interactive graphical logons, dual-monitor configurations, and local console access function normally.
* **Clean Baseline Alignment**: Eliminates redundant out-of-band server management code paths from the Tier 0 administrative platform.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the PAW GPO (e.g., `GPO_Hardening_PAW`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\System Services`
4. Locate `Special Administration Console Helper` (`sacsvr`), double-click to define the policy, and select **Disabled**.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

[Download Script: Configure-DisablePawsacsvr.ps1](../implementation_scripts/Configure-DisablePawsacsvr.ps1)

```powershell
# Configure-DisablePawsacsvr.ps1
# Description: Disables the unnecessary Special Administration Console Helper (sacsvr) service on the local PAW.

Write-Host "Applying hardening requirement: Disable Special Administration Console Helper service on PAW..." -ForegroundColor Cyan

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

*To verify the startup type of this unnecessary service on the PAW:*

[Download Script: Get-PawsacsvrStatus.ps1](../audit_scripts/Get-PawsacsvrStatus.ps1)

```powershell
# Get-PawsacsvrStatus.ps1
# Description: Audits the startup configuration of Special Administration Console Helper (sacsvr) service on the local PAW system.

Write-Host "--- Auditing Special Administration Console Helper (sacsvr) Service on PAW ---" -ForegroundColor Cyan

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
* **ANSSI Active Directory Hardening Guide**: Recommendations on limiting active background services on sensitive hosts
* **DoD Windows 11 Computer STIG v2r6**: Unnecessary services restrictions
