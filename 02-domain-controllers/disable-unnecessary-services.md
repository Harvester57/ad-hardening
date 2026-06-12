# Hardening Requirement: Disable Unnecessary Services on Domain Controllers

## Target Scope
* **Applicable Systems**: Domain Controllers (DCs) running Windows Server.
* **Operating Systems**: Windows Server 2016, Windows Server 2019, Windows Server 2022.

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**:
  * Computer Configuration\Preferences\Windows Settings\Registry
  * HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\Start

---

## Rationale
Domain Controllers are the core authority within an Active Directory forest (Tier 0). Minimizing the running services on these critical systems reduces the overall attack surface and limits potential targets for local privilege escalation, remote exploit execution, or credential extraction.

Disabling non-essential services aligns with the principle of least functionality. In accordance with the Microsoft security guidelines for system services, services can be categorized by whether they should be disabled, are OK to disable if unused, or are already disabled by default.

---

## Technical Services Baselines

The following tables list default services in Windows Server and their hardening recommendations.

### Services That Should Be Disabled
These services present an unnecessary security risk and should be disabled on all Domain Controllers.

| Service Name | Display Name | Purpose & Security Implications |
| :--- | :--- | :--- |
| `XblAuthManager` | Xbox Live Auth Manager | Provides gaming authentication functions; irrelevant to server infrastructure. |
| `XblGameSave` | Xbox Live Game Save | Provides gaming save functions; irrelevant to server infrastructure. |

### Additional Services That Can Be Disabled (OK to Disable)
These services are installed by default but are not required for Domain Controller functionality. They should be disabled to minimize the attack surface.

| Service Name | Display Name | Purpose & Security Implications |
| :--- | :--- | :--- |
| `AxInstSV` | ActiveX Installer (AxInstSV) | Validates ActiveX controls. Domain Controllers should never run ActiveX controls. |
| `bthserv` | Bluetooth Support Service | Supports Bluetooth devices; unnecessary on server systems. |
| `CDPUserSvc` | CDPUserSvc | Connected Devices Platform User Service; syncs user activity data across devices. |
| `PimIndexMaintenanceSvc` | Contact Data | Manages contact data indexing; unnecessary on directory servers. |
| `dmwappushservice` | dmwappushsvc | WAP Push Message Routing Service; used for diagnostics and telemetry. |
| `MapsBroker` | Downloaded Maps Manager | Enables access to downloaded maps; irrelevant to server roles. |
| `lfsvc` | Geolocation Service | Monitors system location; represents a privacy and security risk. |
| `SharedAccess` | Internet Connection Sharing (ICS) | Provides network address translation; represents a networking security risk. |
| `lltdsvc` | Link-Layer Topology Discovery Mapper | Discovers network topology; unnecessary exposure of server network location. |
| `wlidsvc` | Microsoft Account Sign-in Assistant | Enables user signing with Microsoft Accounts; unnecessary on directory servers. |
| `NgcSvc` | Microsoft Passport | Part of Windows Hello for Business; not needed if Windows Hello is not deployed. |
| `NgcCtnrSvc` | Microsoft Passport Container | Part of Windows Hello for Business container management. |
| `NcbService` | Network Connection Broker | Broker for background network connections for modern apps. |
| `PhoneSvc` | Phone Service | Manages telephony state; irrelevant to server infrastructure. |
| `PrintNotify` | Printer Extensions and Notifications | Handles printer notification dialogs; unnecessary on servers. |
| `PcaSvc` | Program Compatibility Assistant Service | Detects application compatibility issues; unnecessary on highly controlled DCs. |
| `QWAVE` | Quality Windows Audio Video Experience | Multimedia streaming quality service; irrelevant to server systems. |
| `RmSvc` | Radio Management Service | Controls radio transmitters (cellular, Wi-Fi); irrelevant to servers. |
| `SensorDataService` | Sensor Data Service | Handles data from system sensors; irrelevant to servers. |
| `SensrSvc` | Sensor Monitoring Service | Monitors system sensors; irrelevant to servers. |
| `SensorService` | Sensor Service | Core sensor service; irrelevant to servers. |
| `ShellHWDetection` | Shell Hardware Detection | Provides notifications for AutoPlay hardware events; can be disabled. |
| `ScDeviceEnum` | Smart Card Device Enumeration Service | Detects smart cards; can be disabled if smart cards are not used for authentication. |
| `SSDPSRV` | SSDP Discovery | Discovers UPnP devices; introduces broadcast name discovery vulnerabilities. |
| `WiaRpc` | Still Image Acquisition Events | Still image capturing events; irrelevant to servers. |
| `OneSyncSvc` | Sync Host | Synchronizes mail, contacts, calendar; irrelevant to servers. |
| `upnphost` | UPnP Device Host | Allows hosting of UPnP devices; represents unnecessary network exposure. |
| `UserDataSvc` | User Data Access | Manages user structured data; irrelevant to servers. |
| `UnistoreSvc` | User Data Storage | Stores user data; irrelevant to servers. |
| `WalletService` | WalletService | Used by Wallet application; irrelevant to servers. |
| `Audiosrv` | Windows Audio | Manages system audio; servers do not require audio capabilities. |
| `AudioEndpointBuilder` | Windows Audio Endpoint Builder | Manages audio endpoints; servers do not require audio capabilities. |
| `FrameServer` | Windows Camera Frame Server | Enables access to system camera feeds; irrelevant to servers. |
| `stisvc` | Windows Image Acquisition (WIA) | Image acquisition from scanners/cameras; irrelevant to servers. |
| `wisvc` | Windows Insider Service | Handles Windows Insider settings; unnecessary on production servers. |
| `icssvc` | Windows Mobile Hotspot Service | Shares internet connection as hotspot; introduces wireless routing security risk. |
| `WpnService` | Windows Push Notifications System Service | System service for push notifications; irrelevant to servers. |
| `WpnUserService` | Windows Push Notifications User Service | User service for push notifications; irrelevant to servers. |

*Note: The Print Spooler (`Spooler`) service is also listed as OK to disable on non-print servers, but it is managed separately as a High-priority control for Domain Controllers.*

### Default Services Already Disabled in Windows Server 2016+
These services are disabled by default. Administrators must ensure they are not manually re-enabled without verification.

| Service Name | Display Name | Purpose & Security Implications |
| :--- | :--- | :--- |
| `tzautoupdate` | Auto Time Zone Updater | Automatically sets the system time zone. |
| `Browser` | Computer Browser | Maintains network host list; legacy and insecure. |
| `AppVClient` | Microsoft App-V Client | Virtualizes applications; disabled by default unless deployed. |
| `NetTcpPortSharing` | Net.Tcp Port Sharing Service | Shares net.tcp ports; disabled by default. |
| `CscService` | Offline Files | Synchronizes offline files cache; disabled by default. |
| `RemoteAccess` | Routing and Remote Access | Provides routing and VPN services; disabled by default. |
| `SCardSvr` | Smart Card | Manages smart cards; disabled by default (must be enabled if smart cards are used). |
| `UevAgentService` | User Experience Virtualization Service | Synchronizes application settings; disabled by default. |
| `WSearch` | Windows Search | Indexes search queries; disabled by default on Windows Server. |

### Critical Services That Must Not Be Disabled (Do Not Disable)
The following services are essential for system stability, network roles, administration, or virtualization integration, and must not be disabled.

> [!WARNING]
> Disabling any of the services listed below will severely degrade or completely break core system functionality, remote management access, or hypervisor integrations. Under no circumstances should these services be disabled.

| Service Name | Display Name | Purpose & Impact of Disabling (Microsoft Rationale) |
| :--- | :--- | :--- |
| `AppReadiness` | App Readiness | Gets apps ready for use the first time a user signs in. Essential for proper initialization of Desktop Experience. |
| `HvHost` | HV Host Service | Performance enhancers for guest VMs. Not used today except for explicitly populated VMs, but Application Guard can also use it. |
| `vmickvpexchange` | Hyper-V Data Exchange Service | Hyper-V integration driver. Performance enhancers for guest VMs. |
| `vmicguestinterface` | Hyper-V Guest Service Interface | Hyper-V integration driver. Performance enhancers for guest VMs. |
| `vmicshutdown` | Hyper-V Guest Shutdown Service | Hyper-V integration driver. Performance enhancers for guest VMs. |
| `vmicheartbeat` | Hyper-V Heartbeat Service | Hyper-V integration driver. Performance enhancers for guest VMs. |
| `vmicvmsession` | Hyper-V PowerShell Direct Service | Hyper-V integration driver. Performance enhancers for guest VMs. |
| `vmicrdv` | Hyper-V Remote Desktop Virtualization Service | Hyper-V integration driver. Performance enhancers for guest VMs. |
| `vmictimesync` | Hyper-V Time Synchronization Service | Hyper-V integration driver. Performance enhancers for guest VMs. |
| `vmicvss` | Hyper-V Volume Shadow Copy Requestor | Hyper-V integration driver. Performance enhancers for guest VMs. |
| `MSiSCSI` | Microsoft iSCSI Initiator Service | Microsoft diagnostic data indicates the system uses this service on both client and server, so there is no benefit to disabling it. |
| `smphost` | Microsoft Storage Spaces SMP | Storage management service. Disabling impacts storage provisioning and storage spaces configuration. |
| `SessionEnv` | Remote Desktop Configuration | Coordinates configuration and properties of RDP sessions; required for Remote Desktop Services. |
| `TermService` | Remote Desktop Services | Required for remote management and administrative access via RDP. |
| `UmRdpService` | Remote Desktop Services UserMode Port Redirector | Supports redirections (such as printers and drives) on the server side of the connection. |
| `RemoteRegistry` | Remote Registry | Essential for remote server management, remote configuration auditing, and vulnerability scanning tools. |
| `SstpSvc` | Secure Socket Tunneling Protocol Service | Disabling this service breaks Routing and Remote Access Service (RRAS). |
| `SamSs` | Security Accounts Manager | Core security authority that manages local security account info; required for system startup and security enforcement. |
| `LanmanServer` | Server | Needed for remote management, IPC$, and SMB file sharing (which is required for SYSVOL and GPO replication). |
| `SystemEventsBroker` | System Events Broker | Despite this service's description implying it is only for WinRT apps, it is also needed for Task Scheduler, Broker Infrastructure Service, and other internal components. |
| `TapiSrv` | Telephony | Disabling this service breaks Routing and Remote Access Service (RRAS). |
| `Themes` | Themes | Cannot set accessibility themes when this service is disabled. |
| `tiledatamodelsvc` | Tile Data model server | The Start menu breaks if you disable this service. |
| `TimeBrokerSvc` | Time Broker | Despite this service's name implying it is only for WinRT apps, it is needed for Task Scheduler, Broker Infrastructure Service, and other internal components. |
| `TabletInputService` | Touch Keyboard and Handwriting Panel Service | Do not disable if Desktop Experience is installed. |
| `UsoSvc` | Update Orchestrator Service for Windows Update | Windows Update, including Windows Server Update Services (WSUS), depends on this service. |
| `WerSvc` | Windows Error Reporting Service | Collects and sends data when a program crashes or stops responding, which both Microsoft and third-party Software Vendors use to diagnose crash-inducing bugs and security bugs. Also needed for Corporate Error Reporting. |
| `Wecsvc` | Windows Event Collector | Collects ETW events, including security events, for manageability and diagnostics. A lot of features and third-party tools rely on it, including security audit tools. |
| `WinRM` | Windows Remote Management (WS-Management) | Needed for remote management and administration via PowerShell Direct and Windows Admin Center. |
| `WinHttpAutoProxySvc` | WinHTTP Web Proxy Auto-Discovery Service | Anything that uses the network stack can have a functional dependency on this service. Many organizations rely on this to configure their internal networks' HTTP proxy routing. Without it, internally-originating HTTP connections to the Internet will all fail. |

---

## Legacy Impact & Compatibility
* **No Functional Impact**: Disabling the specified services has no operational impact on Active Directory Domain Services, replication, group policy processing, client authentication, or administrative management tools.
* **Smart Cards**: If your domain relies on Smart Card authentication, the Smart Card Device Enumeration Service (`ScDeviceEnum`) and Smart Card (`SCardSvr`) services must remain enabled.
* **Desktop Experience Feature Scope**: The specified services are primarily present on Windows Server installations with Desktop Experience. On Windows Server Core installations, most of these services are not installed by default, and attempts to stop or disable them will simply be skipped.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

Because many of these services are not managed through standard GPO Administrative Templates (ADMX), they should be disabled by configuring Group Policy Preferences (GPP) for the registry:

1. Open the **Group Policy Management Console** (`gpmc.msc`) on a domain management host.
2. Edit the GPO linked to your Domain Controllers Organizational Unit (e.g., `GPO_Hardening_DomainControllers`).
3. Navigate to:
   `Computer Configuration\Preferences\Windows Settings\Registry`
4. For each service listed below, create a new Registry Preference (Right-click **Registry -> New -> Registry Item**):
   * **Action**: `Update`
   * **Hive**: `HKEY_LOCAL_MACHINE`
   * **Key Path**: `SYSTEM\CurrentControlSet\Services\<ServiceName>` (e.g., `SYSTEM\CurrentControlSet\Services\XblAuthManager`)
   * **Value name**: `Start`
   * **Value type**: `REG_DWORD`
   * **Value data**: `4`

Apply this registry change for the service names listed in the tables above.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script to configure the registry settings and stop the services locally:

[Download Script: Configure-DisableUnnecessaryServices.ps1](implementation_scripts/Configure-DisableUnnecessaryServices.ps1)

```powershell
# Configure-DisableUnnecessaryServices.ps1
# Description: Stops and disables unnecessary services on Domain Controllers.

Write-Host "Applying hardening requirement: Disable Unnecessary Services on Domain Controllers..." -ForegroundColor Cyan

$services = @(
    "XblAuthManager",
    "XblGameSave",
    "AxInstSV",
    "bthserv",
    "CDPUserSvc",
    "PimIndexMaintenanceSvc",
    "dmwappushservice",
    "MapsBroker",
    "lfsvc",
    "SharedAccess",
    "lltdsvc",
    "wlidsvc",
    "NgcSvc",
    "NgcCtnrSvc",
    "NcbService",
    "PhoneSvc",
    "PrintNotify",
    "PcaSvc",
    "QWAVE",
    "RmSvc",
    "SensorDataService",
    "SensrSvc",
    "SensorService",
    "ShellHWDetection",
    "ScDeviceEnum",
    "SSDPSRV",
    "WiaRpc",
    "OneSyncSvc",
    "upnphost",
    "UserDataSvc",
    "UnistoreSvc",
    "WalletService",
    "Audiosrv",
    "AudioEndpointBuilder",
    "FrameServer",
    "stisvc",
    "wisvc",
    "icssvc",
    "WpnService",
    "WpnUserService"
)

foreach ($serviceName in $services) {
    Write-Host "Processing service $($serviceName)..." -ForegroundColor Gray
    
    # Stop the service if it is running
    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($service) {
        if ($service.Status -eq "Running") {
            Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
            Write-Host "  Service $($serviceName) stopped." -ForegroundColor Gray
        }
    }

    # Disable the service startup in registry
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName"
    if (Test-Path $regPath) {
        Set-ItemProperty -Path $regPath -Name "Start" -Value 4 -Type DWord
        Write-Host "  Service $($serviceName) startup disabled in registry." -ForegroundColor Green
    } else {
        Write-Host "  Service $($serviceName) is not installed." -ForegroundColor Gray
    }
}

Write-Host "Remediation completed successfully." -ForegroundColor Cyan
```

*To verify that the services have been disabled:*

[Download Script: Get-UnnecessaryServicesStatus.ps1](audit_scripts/Get-UnnecessaryServicesStatus.ps1)

```powershell
# Get-UnnecessaryServicesStatus.ps1
# Description: Audits the registry startup state of unnecessary system services.

Write-Host "--- Auditing Unnecessary Services on Domain Controllers ---" -ForegroundColor Cyan

$services = @(
    "XblAuthManager",
    "XblGameSave",
    "AxInstSV",
    "bthserv",
    "CDPUserSvc",
    "PimIndexMaintenanceSvc",
    "dmwappushservice",
    "MapsBroker",
    "lfsvc",
    "SharedAccess",
    "lltdsvc",
    "wlidsvc",
    "NgcSvc",
    "NgcCtnrSvc",
    "NcbService",
    "PhoneSvc",
    "PrintNotify",
    "PcaSvc",
    "QWAVE",
    "RmSvc",
    "SensorDataService",
    "SensrSvc",
    "SensorService",
    "ShellHWDetection",
    "ScDeviceEnum",
    "SSDPSRV",
    "WiaRpc",
    "OneSyncSvc",
    "upnphost",
    "UserDataSvc",
    "UnistoreSvc",
    "WalletService",
    "Audiosrv",
    "AudioEndpointBuilder",
    "FrameServer",
    "stisvc",
    "wisvc",
    "icssvc",
    "WpnService",
    "WpnUserService"
)

$vulnerableCount = 0

foreach ($serviceName in $services) {
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName"
    if (Test-Path $regPath) {
        $startVal = Get-ItemProperty -Path $regPath -Name "Start" -ErrorAction SilentlyContinue
        if ($startVal) {
            $start = $startVal.Start
            if ($start -eq 4) {
                Write-Host "[+] Service $($serviceName) is secure (Disabled)." -ForegroundColor Green
            } else {
                Write-Host "[!] VULNERABLE: Service $($serviceName) startup type is not Disabled (Start value is $($start))." -ForegroundColor Red
                $vulnerableCount = $vulnerableCount + 1
            }
        } else {
            Write-Host "[!] VULNERABLE: Service $($serviceName) exists but Start registry value is missing." -ForegroundColor Red
            $vulnerableCount = $vulnerableCount + 1
        }
    } else {
        Write-Host "[+] Service $($serviceName) is not installed (Secure)." -ForegroundColor Green
    }
}

if ($vulnerableCount -gt 0) {
    Write-Host "Audit failed: $($vulnerableCount) service(s) are not disabled." -ForegroundColor Red
} else {
    Write-Host "Audit passed: All non-essential services are disabled or not installed." -ForegroundColor Green
}
```

---

## Sources & Compliance References
* **Microsoft Windows Server Security Guidance**: [Security guidelines for disabling system services in Windows Server](https://learn.microsoft.com/en-us/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server)
* **ANSSI AD Hardening Guide**: Recommendation R4 (Minimization of service execution and software installation)
* **CIS Microsoft Windows Server Benchmark**: Section 2.2 (User Rights Assignment) and general service minimization baselines
