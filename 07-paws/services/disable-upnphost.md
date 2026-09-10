# [REQ-PAW-048] Disable UPnP Device Host Service for PAWs (upnphost)

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration. *(For standard client workstations and member servers, refer to baseline [REQ-END-048](../../08-endpoints/services/disable-upnphost.md); for Domain Controllers, refer to [REQ-DC-063](../../02-domain-controllers/services/disable-upnphost.md)).*
* **Operating Systems**: Windows 10 Enterprise (all supported builds) and Windows 11 Enterprise.

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
The UPnP Device Host service (`upnphost`) allows a host to configure, announce, and expose dynamic Universal Plug and Play (UPnP) devices and control points to the local area network over unauthenticated HTTP endpoints.

### 1. Inherent Insecurity of UPnP Device Hosting
The UPnP Device Architecture (UDA) contains severe security deficiencies that are incompatible with hardened environments:
* **Unauthenticated Network Control**: UPnP control actions are transmitted via HTTP SOAP requests that do not require cryptographic authentication, integrity checks, or role-based access control. Any network entity on the local subnet can trigger device actions or modify device state.
* **Perimeter and Firewall Bypassing (IGD Abuse)**: Malicious implants or compromised local processes can exploit UPnP Internet Gateway Device (IGD) functionality to instruct perimeter routers and firewalls to create inbound port forward mappings, establishing unmonitored persistence and bypassing perimeter network defenses.
* **Network Parser Attack Surface**: The `upnphost` service parses complex XML descriptors and HTTP control requests from arbitrary network nodes, exposing the host to memory corruption and remote code execution vulnerabilities in system network libraries.

### 2. PAW Clean Source Integrity and Boundary Protection
Privileged Access Workstations represent the highest tier of administrative trust in the Active Directory forest:
* **Strict Boundary Isolation**: PAWs must maintain an impenetrable network perimeter. Operating a background service that listens on local network sockets and processes unauthenticated XML and SOAP control payloads directly violates the clean source principle.
* **Unidirectional Administrative Flows**: Tier 0 administrative operations strictly require outbound, authenticated, and encrypted connections (such as WinRM/HTTPS and RPC/Kerberos) to domain controllers and critical infrastructure. PAWs must never act as network device hosts or advertise services to adjacent systems.
* **Driver and Socket Minimization**: Disabling `upnphost` ensures that the operating system refuses all inbound UPnP device interaction requests, eliminating listening sockets and safeguarding Tier 0 administrative credentials.

### 3. MITRE ATT&CK Mapping
* **T1210 - Exploitation of Remote Services**: Exploitation of memory corruption and parsing vulnerabilities in UPnP network listeners.
* **T1562.004 - Impair Defenses: Disable or Modify System Firewall**: Abusing UPnP IGD to automatically establish unauthorized inbound firewall pinholes.
* **T1046 - Network Service Discovery**: Adversaries discover exposed UPnP services to map administrative endpoints.

---

## Legacy Impact & Compatibility
* **Tier 0 Administrative Management**: Disabling the UPnP Device Host service has zero impact on Active Directory administration, server management tools (RSAT), PowerShell remoting, or Hyper-V administration.
* **Device Isolation**: PAWs should never host or discover consumer UPnP multimedia devices. All administrative hardware (smart card readers, YubiKeys, hardware security modules) uses secure, local USB driver stacks and is unaffected.
* **Clean Source Perimeter**: Prevents rogue applications from opening network listeners or modifying gateway routing tables.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the PAW GPO (e.g., `GPO_Hardening_PAW`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\System Services`
4. Locate `UPnP Device Host` (`upnphost`), double-click to define the policy, and select **Disabled**.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

[Download Script: Configure-DisablePawupnphost.ps1](../implementation_scripts/Configure-DisablePawupnphost.ps1)

```powershell
# Configure-DisablePawupnphost.ps1
# Description: Disables the unnecessary UPnP Device Host (upnphost) service on the local PAW.

Write-Host "Applying hardening requirement: Disable UPnP Device Host service on PAW..." -ForegroundColor Cyan

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

*To verify the startup type of this unnecessary service on the PAW:*

[Download Script: Get-PawupnphostStatus.ps1](../audit_scripts/Get-PawupnphostStatus.ps1)

```powershell
# Get-PawupnphostStatus.ps1
# Description: Audits the startup configuration of UPnP Device Host (upnphost) service on the local PAW system.

Write-Host "--- Auditing UPnP Device Host (upnphost) Service on PAW ---" -ForegroundColor Cyan

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
* **ANSSI Active Directory Hardening Guide**: Recommendations on limiting active background services on sensitive hosts
* **DoD Windows 11 Computer STIG v2r6**: Unnecessary services restrictions
