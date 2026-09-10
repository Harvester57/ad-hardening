# [REQ-END-048] Disable UPnP Device Host Service (upnphost)

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers. *(For Tier 0 Privileged Access Workstations, refer to tightened baseline [REQ-PAW-048](../../07-paws/services/disable-upnphost.md); for Domain Controllers, refer to [REQ-DC-063](../../02-domain-controllers/services/disable-upnphost.md)).*
* **Operating Systems**: Windows 10 (all supported editions), Windows 11 Enterprise/Pro, Windows Server 2016, 2019, 2022, and 2025.

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\System Services\UPnP Device Host` -> **Disabled**
  * **Registry Path**: `HKLM\SYSTEM\CurrentControlSet\Services\upnphost`
  * **Value Name**: `Start`
  * **Value Type**: `REG_DWORD`
  * **Value Data**: `4` (Disabled)

---

## Rationale
The UPnP Device Host service (`upnphost`) enables a Windows endpoint to announce, configure, and host dynamic Universal Plug and Play (UPnP) devices and control points. When software components or peripherals register with `upnphost`, the service publishes XML device descriptions and listens on local HTTP endpoints to process incoming UPnP SOAP control actions.

### 1. Inherent Insecurity of UPnP Device Hosting
The UPnP architecture was designed for zero-configuration residential networking and contains structural security flaws:
* **Absence of Authentication**: Standard UPnP device control protocols lack authentication, integrity signing, or role-based access controls. Any network actor on the local subnet can issue SOAP requests to control published services, extract device configuration data, or trigger device actions.
* **Firewall and Perimeter Bypassing (IGD Abuse)**: UPnP Internet Gateway Device (IGD) mechanisms enable local applications or malware running with standard user privileges to request automatic incoming port mappings on perimeter firewalls and routers. Attackers exploit UPnP to establish persistent inbound tunnels, bypass perimeter inspection, and expose internal services directly to external networks without administrative privileges or audit logging.
* **Memory Corruption and Parser Vulnerabilities**: The `upnphost` service continuously processes XML device descriptions, SOAP payloads, and HTTP control requests from arbitrary network nodes. Historically, UPnP hosting components have been subject to buffer overflows and memory corruption vulnerabilities allowing remote code execution.

### 2. Least Functionality in Enterprise Environments
Enterprise environments require strict control over network services and listening ports:
* Workstations and member servers must never function as UPnP device hosts or expose unauthenticated control interfaces to the local network.
* Disabling the `upnphost` service eliminates listening HTTP endpoints, prevents rogue software from abusing UPnP port mapping, and reduces the endpoint's exposed attack surface.

### 3. MITRE ATT&CK Mapping
* **T1210 - Exploitation of Remote Services**: Exploitation of memory corruption and parser flaws in UPnP network listeners.
* **T1562.004 - Impair Defenses: Disable or Modify System Firewall**: Abusing UPnP IGD to automatically create inbound firewall pinholes and bypass perimeter defenses.
* **T1046 - Network Service Discovery**: Adversaries discover exposed UPnP services to enumerate local host capabilities.

---

## Legacy Impact & Compatibility
* **Corporate Applications**: Standard Active Directory domain services, enterprise productivity suites, and line-of-business software do not rely on UPnP Device Host. Disabling this service is fully transparent.
* **Consumer Media Devices**: Streaming media to UPnP/DLNA renderers (e.g., smart TVs, media players) is disabled. In enterprise environments, these capabilities should not be supported on managed workstations.
* **Administrative Operations**: Remote management via WinRM, PowerShell Remoting, WMI, and Group Policy remains fully functional.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the target endpoints GPO (e.g., `GPO_Hardening_Endpoints`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\System Services`
4. Locate `UPnP Device Host` (`upnphost`), double-click to define the policy, and select **Disabled**.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

[Download Script: Configure-Disableupnphost.ps1](../implementation_scripts/Configure-Disableupnphost.ps1)

```powershell
# Configure-Disableupnphost.ps1
# Description: Disables the unnecessary UPnP Device Host (upnphost) service.

Write-Host "Applying hardening requirement: Disable UPnP Device Host service..." -ForegroundColor Cyan

$ServiceName = "upnphost"
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

[Download Script: Get-upnphostStatus.ps1](../audit_scripts/Get-upnphostStatus.ps1)

```powershell
# Get-upnphostStatus.ps1
# Description: Audits the startup configuration of UPnP Device Host (upnphost) service.

Write-Host "--- Auditing UPnP Device Host (upnphost) Service ---" -ForegroundColor Cyan

$ServiceName = "upnphost"
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
* **CIS Microsoft Windows Client Benchmark**: Section 5.33 (upnphost)
* **ANSSI Active Directory Hardening Guide**: Recommendations on host service minimization
* **DoD Windows 11 Computer STIG v2r6**: Unnecessary services restrictions
