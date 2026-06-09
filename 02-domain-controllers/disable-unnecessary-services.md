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

Unnecessary services, particularly those meant for client features or consumer hardware support, introduce vulnerabilities and complexity. For example:
1. **Xbox Live Services**: Services such as Xbox Live Auth Manager (`XblAuthManager`) and Xbox Live Game Save (`XblGameSave`) are installed on Windows Server installations containing the Desktop Experience. These services provide gaming functions that are entirely irrelevant to server infrastructure and represent unnecessary exposure.
2. **ActiveX Installer**: The ActiveX Installer service (`AxInstSV`) validates ActiveX controls. A Domain Controller should never browse websites or execute ActiveX controls, making this service a potential risk.
3. **Consumer & Hardware Integration Services**: Services like Bluetooth Support (`bthserv`), Geolocation (`lfsvc`), Phone Service (`PhoneSvc`), Sensor Services (`SensorService`, `SensorDataService`, `SensrSvc`), and Windows Camera Frame Server (`FrameServer`) should never run on a Domain Controller.

Disabling these non-essential services aligns with the principle of least functionality.

---

## Legacy Impact & Compatibility
* **No Functional Impact**: Disabling the specified services has no operational impact on Active Directory Domain Services, replication, group policy processing, client authentication, or administrative management tools.
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

Apply this registry change for the following service names:
* `XblAuthManager` (Xbox Live Auth Manager)
* `XblGameSave` (Xbox Live Game Save)
* `AxInstSV` (ActiveX Installer)
* `bthserv` (Bluetooth Support Service)
* `lfsvc` (Geolocation Service)
* `MapsBroker` (Downloaded Maps Manager)
* `PhoneSvc` (Phone Service)
* `SensorService` (Sensor Service)
* `SensorDataService` (Sensor Data Service)
* `SensrSvc` (Sensor Monitoring Service)
* `FrameServer` (Windows Camera Frame Server)
* `icssvc` (Windows Mobile Hotspot Service)

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script to configure the registry settings and stop the services locally:

```powershell
# Configure-DisableUnnecessaryServices.ps1
# Description: Stops and disables unnecessary services on Domain Controllers.

Write-Host "Applying hardening requirement: Disable Unnecessary Services on Domain Controllers..." -ForegroundColor Cyan

$services = @(
    "XblAuthManager",
    "XblGameSave",
    "AxInstSV",
    "bthserv",
    "lfsvc",
    "MapsBroker",
    "PhoneSvc",
    "SensorService",
    "SensorDataService",
    "SensrSvc",
    "FrameServer",
    "icssvc"
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

```powershell
# Get-UnnecessaryServicesStatus.ps1
# Description: Audits the registry startup state of unnecessary system services.

Write-Host "--- Auditing Unnecessary Services on Domain Controllers ---" -ForegroundColor Cyan

$services = @(
    "XblAuthManager",
    "XblGameSave",
    "AxInstSV",
    "bthserv",
    "lfsvc",
    "MapsBroker",
    "PhoneSvc",
    "SensorService",
    "SensorDataService",
    "SensrSvc",
    "FrameServer",
    "icssvc"
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
