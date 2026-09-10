# [REQ-PAW-043] Disable Remote Procedure Call (RPC) Locator Service for PAWs (RpcLocator)

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration. *(For standard client workstations and member servers, refer to baseline [REQ-END-043](../../08-endpoints/services/disable-rpclocator.md)).*
* **Operating Systems**: Windows 10 Enterprise (all supported builds) and Windows 11 Enterprise.

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\System Services\Remote Procedure Call (RPC) Locator` -> **Disabled**
  * **Registry Path**: `HKLM\SYSTEM\CurrentControlSet\Services\RpcLocator`
  * **Value Name**: `Start`
  * **Value Type**: `REG_DWORD`
  * **Value Data**: `4` (Disabled)

---

## Rationale
The Remote Procedure Call (RPC) Locator service (`RpcLocator`) manages the legacy RPC name service database, historically used in pre-Windows 2000 architectures to locate RPC server interfaces.

### 1. Legacy RPC Vulnerability Surface on Administrative Hosts
Operating deprecated RPC subsystems on Tier 0 administrative workstations introduces unnecessary risks:
* **Legacy Named Pipe Exposure**: When active, `RpcLocator` binds legacy RPC named pipe endpoints (such as `\pipe\locator`). These interfaces lack modern RPC authentication controls and packet integrity signing, providing potential avenues for local privilege escalation and unauthenticated inter-process manipulation.
* **Deprecation and Lack of Maintenance**: Microsoft deprecated the RPC Locator service in Windows XP / Windows Server 2003, replacing it with the dynamic RPC Endpoint Mapper (`RpcSs`) and DNS/LDAP service records. Retaining deprecated service binaries in memory creates unneeded exploit surface.

### 2. PAW Clean Source and Deprecated Subsystem Decommissioning
Under the clean source principle and Microsoft PAW guidelines:
* **Minimalist Software Architecture**: Privileged Access Workstations must run the absolute minimum set of operating system subsystems required for Tier 0 directory administration. Retaining non-functional legacy code from legacy Windows NT releases violates baseline minimization principles.
* **Modern Directory Administration Standards**: Tier 0 administrative operations (Active Directory Users and Computers, Group Policy Management, Active Directory Administrative Center, PowerShell Remoting) rely exclusively on the modern RPC Endpoint Mapper (TCP port 135) with mandatory Kerberos mutual authentication. PAWs have zero reliance on legacy RPC name resolution.
* **Driver and Endpoint Deallocation**: Disabling `RpcLocator` guarantees that no legacy RPC name service endpoints are registered on the system.

### 3. MITRE ATT&CK Mapping
* **T1210 - Exploitation of Remote Services**: Exploitation of legacy RPC interface parsers.
* **T1021.002 - Remote Services: SMB/Windows Admin Shares**: Interaction with legacy named pipe interfaces.
* **T1046 - Network Service Discovery**: Probing legacy RPC endpoints to map host vulnerabilities.

---

## Legacy Impact & Compatibility
* **Tier 0 Administrative Management**: Disabling `RpcLocator` has zero impact on Active Directory administration, server management tools (RSAT), PowerShell remoting, or Hyper-V administration.
* **Strict Modern Tooling Requirement**: PAWs are dedicated, freshly provisioned administrative platforms that run only modern, supported management utilities; legacy applications requiring Windows NT 4.0 RPC locator functions are strictly prohibited on PAWs.
* **Clean Baseline Alignment**: Eliminates redundant legacy code paths from the administrative operating system.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the PAW GPO (e.g., `GPO_Hardening_PAW`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\System Services`
4. Locate `Remote Procedure Call (RPC) Locator` (`RpcLocator`), double-click to define the policy, and select **Disabled**.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

[Download Script: Configure-DisablePawRpcLocator.ps1](../implementation_scripts/Configure-DisablePawRpcLocator.ps1)

```powershell
# Configure-DisablePawRpcLocator.ps1
# Description: Disables the unnecessary Remote Procedure Call (RPC) Locator (RpcLocator) service on the local PAW.

Write-Host "Applying hardening requirement: Disable Remote Procedure Call (RPC) Locator service on PAW..." -ForegroundColor Cyan

$ServiceName = "RpcLocator"
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

[Download Script: Get-PawRpcLocatorStatus.ps1](../audit_scripts/Get-PawRpcLocatorStatus.ps1)

```powershell
# Get-PawRpcLocatorStatus.ps1
# Description: Audits the startup configuration of Remote Procedure Call (RPC) Locator (RpcLocator) service on the local PAW system.

Write-Host "--- Auditing Remote Procedure Call (RPC) Locator (RpcLocator) Service on PAW ---" -ForegroundColor Cyan

$ServiceName = "RpcLocator"
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
* **CIS Microsoft Windows Client Benchmark**: Section 5.25 (RpcLocator)
* **ANSSI Active Directory Hardening Guide**: Recommendations on limiting active background services on sensitive hosts
* **DoD Windows 11 Computer STIG v2r6**: Unnecessary services restrictions
