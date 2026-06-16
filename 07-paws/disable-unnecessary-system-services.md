# [REQ-PAW-028] Disable Unnecessary System Services for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration.
* **Operating Systems**: Windows 10 Enterprise (1607+) and Windows 11 Enterprise.

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\System Services`
  * **Registry Location**: `HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\Start`

---

## Rationale
To minimize the attack surface of standard client endpoints and member servers, all unnecessary system services must be disabled. Operating system services that are not required for core administrative tasks or business functionality introduce unnecessary entry points for network exposure, resource utilization, and privilege escalation vulnerabilities:

1. **Legacy and Unused Networking Services**: Services like `Browser` (Computer Browser), `SSDPSRV` (SSDP Discovery), and `upnphost` (UPnP Device Host) listen on network interfaces and present network-based exposure to legacy protocols. SSDP and UPnP have been notoriously targeted for buffer overflows and denial-of-service reflection attacks.
2. **Microsoft Web and FTP Publishing**: Services like `FTPSVC` (FTP Service), `W3SVC` (World Wide Web Publishing Service), and `WMSvc` (Web Management Service) are web/FTP server components that should never be enabled on workstations.
3. **Xbox Integration Services**: Services like `XboxGipSvc` (Xbox Accessory Management Service), `XblAuthManager` (Xbox Live Auth Manager), `XblGameSave` (Xbox Live Game Save), and `XboxNetApiSvc` (Xbox Live Networking Service) are gaming integration libraries that are completely unnecessary in a hardened enterprise environment.
4. **Specialty Services**: Other services like `sshd` (OpenSSH SSH Server), `LxssManager` (WSL / Linux subsystem), `irmon` (Infrared Monitor), `SharedAccess` (Internet Connection Sharing), `RpcLocator` (legacy RPC Locator), `RemoteAccess` (Routing and Remote Access), `simptcp` (Simple TCP/IP Services), `sacsvr` (Special Administration Console Helper), `WMPNetworkSvc` (Windows Media Player Network Sharing), and `icssvc` (Windows Mobile Hotspot Service) present unnecessary management ports or network bridging capabilities that must be closed.

---

## Legacy Impact & Compatibility
* **Infra Compatibility**: Administrative functions relying on legacy RPC Locator or SSDP-based discovery of network printers/devices may be affected.
* **WSL Functionality**: Disabling `LxssManager` prevents running Windows Subsystem for Linux (WSL) containers on PAWs. This is the desired security behavior, as PAWs should not host developer Linux kernels or unvetted container instances.
* **Mobile Hotspotting**: Disabling `icssvc` and `SharedAccess` prevents users from creating cellular hot-spotting configurations or sharing their network cards. This is a desired security behavior.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the PAW GPO (e.g., `GPO_Hardening_PAW`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\System Services`
4. Locate each of the following services, double-click to define the policy, and select **Disabled**:
   * `Computer Browser` (Browser)
   * `Infrared monitor service` (irmon)
   * `Internet Connection Sharing (ICS)` (SharedAccess)
   * `LxssManager` (LxssManager)
   * `Microsoft FTP Service` (FTPSVC)
   * `OpenSSH SSH Server` (sshd)
   * `Remote Procedure Call (RPC) Locator` (RpcLocator)
   * `Routing and Remote Access` (RemoteAccess)
   * `Simple TCP/IP Services` (simptcp)
   * `Special Administration Console Helper` (sacsvr)
   * `SSDP Discovery` (SSDPSRV)
   * `UPnP Device Host` (upnphost)
   * `Web Management Service` (WMSvc)
   * `Windows Media Player Network Sharing Service` (WMPNetworkSvc)
   * `Windows Mobile Hotspot Service` (icssvc)
   * `World Wide Web Publishing Service` (W3SVC)
   * `Xbox Accessory Management Service` (XboxGipSvc)
   * `Xbox Live Auth Manager` (XblAuthManager)
   * `Xbox Live Game Save` (XblGameSave)
   * `Xbox Live Networking Service` (XboxNetApiSvc)

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to disable unnecessary services if they exist on the target operating system.

[Download Script: Disable-PawUnnecessaryServices.ps1](implementation_scripts/Disable-PawUnnecessaryServices.ps1)

```powershell
# Disable-PawUnnecessaryServices.ps1
# Description: Disables unnecessary and high-risk system services on the local PAW.

Write-Host "Disabling unnecessary system services..." -ForegroundColor Cyan

$Services = @(
    "Browser",         # Computer Browser
    "irmon",           # Infrared monitor service
    "SharedAccess",    # Internet Connection Sharing (ICS)
    "LxssManager",     # LxssManager (WSL)
    "FTPSVC",          # Microsoft FTP Service
    "sshd",            # OpenSSH SSH Server
    "RpcLocator",      # Remote Procedure Call (RPC) Locator
    "RemoteAccess",    # Routing and Remote Access
    "simptcp",         # Simple TCP/IP Services
    "sacsvr",          # Special Administration Console Helper
    "SSDPSRV",         # SSDP Discovery
    "upnphost",        # UPnP Device Host
    "WMSvc",           # Web Management Service
    "WMPNetworkSvc",   # Windows Media Player Network Sharing Service
    "icssvc",          # Windows Mobile Hotspot Service
    "W3SVC",           # World Wide Web Publishing Service
    "XboxGipSvc",      # Xbox Accessory Management Service
    "XblAuthManager",  # Xbox Live Auth Manager
    "XblGameSave",     # Xbox Live Game Save
    "XboxNetApiSvc"    # Xbox Live Networking Service
)

foreach ($SvcName in $Services) {
    $Service = Get-Service -Name $SvcName -ErrorAction SilentlyContinue
    if ($null -ne $Service) {
        if ($Service.StartType -ne "Disabled") {
            # Stop the service first if running
            if ($Service.Status -eq "Running") {
                Stop-Service -Name $SvcName -Force -ErrorAction SilentlyContinue | Out-Null
            }
            Set-Service -Name $SvcName -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
            Write-Host "[+] Service '$SvcName' stopped and disabled." -ForegroundColor Green
        } else {
            Write-Host "[~] Service '$SvcName' is already disabled." -ForegroundColor Gray
        }
    } else {
        Write-Host "[~] Service '$SvcName' is not installed." -ForegroundColor Gray
    }
}

Write-Host "Unnecessary services configuration completed." -ForegroundColor Green
```

*To verify the startup type of unnecessary services on the PAW:*

[Download Script: Get-PawUnnecessaryServicesStatus.ps1](audit_scripts/Get-PawUnnecessaryServicesStatus.ps1)

```powershell
# Get-PawUnnecessaryServicesStatus.ps1
# Description: Audits the startup configuration of unnecessary system services on the local PAW system.

Write-Host "--- Auditing Unnecessary System Services ---" -ForegroundColor Cyan

$script:Vulnerable = $false

$Services = @(
    "Browser",
    "irmon",
    "SharedAccess",
    "LxssManager",
    "FTPSVC",
    "sshd",
    "RpcLocator",
    "RemoteAccess",
    "simptcp",
    "sacsvr",
    "SSDPSRV",
    "upnphost",
    "WMSvc",
    "WMPNetworkSvc",
    "icssvc",
    "W3SVC",
    "XboxGipSvc",
    "XblAuthManager",
    "XblGameSave",
    "XboxNetApiSvc"
)

foreach ($SvcName in $Services) {
    $Service = Get-Service -Name $SvcName -ErrorAction SilentlyContinue
    if ($null -ne $Service) {
        $Color = if ($Service.StartType -eq "Disabled") { "Green" } else { "Red" }
        Write-Host "    - Service: $SvcName | StartType: $($Service.StartType) (Expected: Disabled)" -ForegroundColor $Color
        
        if ($Service.StartType -ne "Disabled") {
            $script:Vulnerable = $true
        }
    } else {
        Write-Host "    - Service: $SvcName | Not Installed (Compliant)" -ForegroundColor Green
    }
}

if ($script:Vulnerable) {
    Write-Host "Audit Result: VULNERABLE" -ForegroundColor Red
    exit 1
} else {
    Write-Host "Audit Result: SECURE" -ForegroundColor Green
    exit 0
}
```

---

## Sources & Compliance References
* **CIS Microsoft Windows Client Benchmark**: Section 5.3 (Browser), Section 5.8 (irmon), Section 5.9 (SharedAccess), Section 5.11 (LxssManager), Section 5.12 (FTPSVC), Section 5.14 (sshd), Section 5.25 (RpcLocator), Section 5.27 (RemoteAccess), Section 5.29 (simptcp), Section 5.31 (sacsvr), Section 5.32 (SSDPSRV), Section 5.33 (upnphost), Section 5.34 (WMSvc), Section 5.37 (WMPNetworkSvc), Section 5.38 (icssvc), Section 5.43 (W3SVC), Section 5.44 to 5.47 (Xbox services)
* **ANSSI Active Directory Hardening Guide**: Recommendations on hardening endpoint hosts and limiting active background services on sensitive systems.
* **DoD Windows 11 Computer STIG v2r6**: Services disable requirements
