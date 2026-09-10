# [REQ-END-043] Disable Remote Procedure Call (RPC) Locator Service (RpcLocator)

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers. *(For Tier 0 Privileged Access Workstations, refer to tightened baseline [REQ-PAW-043](../../07-paws/services/disable-rpclocator.md)).*
* **Operating Systems**: Windows 10 (all supported editions), Windows 11 Enterprise/Pro, Windows Server 2016, 2019, 2022, and 2025.

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
The Remote Procedure Call (RPC) Locator service (`RpcLocator`) manages the legacy RPC name service database, originally designed in early Windows NT architectures to allow RPC server applications to publish interface bindings and RPC clients to discover those interfaces by name across network domains.

### 1. Architectural Obsolescence and Attack Surface Reduction
The `RpcLocator` service represents deprecated legacy architecture with no place in modern enterprise environments:
* **Obsolete Name Resolution Mechanism**: Beginning with Windows XP and Windows Server 2003, Microsoft superseded the RPC name service with the dynamic RPC Endpoint Mapper (`RpcSs` running over TCP port 135), Active Directory Domain Services (AD DS) LDAP queries, and Domain Name System (DNS) SRV records.
* **Legacy Named Pipe Exposure**: When running, `RpcLocator` registers legacy RPC endpoints and listens on named pipes (such as `\pipe\locator`). These legacy communication channels were engineered prior to modern RPC security enhancements (e.g., mandatory packet privacy, mutual Kerberos authentication, and strict RPC interface flags), creating unnecessary local attack surface and potential targets for RPC fuzzing and privilege escalation.
* **Zero Native Dependency**: No contemporary Windows operating system component, administrative console, or Active Directory directory service depends on the `RpcLocator` service. Microsoft formally deprecated the service and recommends maintaining it in a disabled state across all Windows versions.

### 2. Least Functionality in Active Directory
In hardened enterprise environments:
* Systems should execute only those services strictly required for business operations and directory communication.
* Disabling `RpcLocator` permanently closes legacy named pipes and deallocates legacy RPC stub libraries, reducing the memory and execution footprint of the endpoint.

### 3. MITRE ATT&CK Mapping
* **T1210 - Exploitation of Remote Services**: Exploiting vulnerabilities in legacy RPC interface parsers and handlers.
* **T1021.002 - Remote Services: SMB/Windows Admin Shares**: Querying or manipulating legacy named pipe bindings.
* **T1046 - Network Service Discovery**: Adversaries probing RPC endpoints to fingerprint legacy operating system versions.

---

## Legacy Impact & Compatibility
* **Active Directory Operations**: Zero impact. Active Directory Domain Services, replication, Group Policy processing, Kerberos ticket acquisition, and Netlogon communicate via the dynamic RPC Endpoint Mapper (`RpcSs`) and do not use `RpcLocator`.
* **Administrative Tooling**: Modern remote administration (PowerShell Remoting, WinRM, WMI, Windows Admin Center, RSAT) is completely unaffected.
* **Legacy Custom Applications**: Only obsolete, proprietary client-server software developed in the late 1990s specifically for Windows NT 4.0 that utilized RpcNs* APIs could be impacted. Such legacy applications should be modernized or retired.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the target endpoints GPO (e.g., `GPO_Hardening_Endpoints`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\System Services`
4. Locate `Remote Procedure Call (RPC) Locator` (`RpcLocator`), double-click to define the policy, and select **Disabled**.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

[Download Script: Configure-DisableRpcLocator.ps1](../implementation_scripts/Configure-DisableRpcLocator.ps1)

```powershell
# Configure-DisableRpcLocator.ps1
# Description: Disables the unnecessary Remote Procedure Call (RPC) Locator (RpcLocator) service.

Write-Host "Applying hardening requirement: Disable Remote Procedure Call (RPC) Locator service..." -ForegroundColor Cyan

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

*To verify the startup type of this unnecessary service:*

[Download Script: Get-RpcLocatorStatus.ps1](../audit_scripts/Get-RpcLocatorStatus.ps1)

```powershell
# Get-RpcLocatorStatus.ps1
# Description: Audits the startup configuration of Remote Procedure Call (RPC) Locator (RpcLocator) service.

Write-Host "--- Auditing Remote Procedure Call (RPC) Locator (RpcLocator) Service ---" -ForegroundColor Cyan

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
* **ANSSI Active Directory Hardening Guide**: Recommendations on host service minimization
* **DoD Windows 11 Computer STIG v2r6**: Unnecessary services restrictions
