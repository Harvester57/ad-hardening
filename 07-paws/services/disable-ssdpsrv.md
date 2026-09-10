# [REQ-PAW-047] Disable SSDP Discovery Service for PAWs (SSDPSRV)

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration. *(For standard client workstations and member servers, refer to baseline [REQ-END-047](../../08-endpoints/services/disable-ssdpsrv.md); for Domain Controllers, refer to [REQ-DC-060](../../02-domain-controllers/services/disable-ssdpsrv.md)).*
* **Operating Systems**: Windows 10 Enterprise (all supported builds) and Windows 11 Enterprise.

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\System Services\SSDP Discovery` -> **Disabled**
  * **Registry Path**: `HKLM\SYSTEM\CurrentControlSet\Services\SSDPSRV`
  * **Value Name**: `Start`
  * **Value Type**: `REG_DWORD`
  * **Value Data**: `4` (Disabled)

---

## Rationale
The Simple Service Discovery Protocol (SSDP) Discovery service (`SSDPSRV`) listens on UDP port 1900 multicast (`239.255.255.250` for IPv4 and `[FF02::C]` / `[FF05::C]` for IPv6) to discover Universal Plug and Play (UPnP) networked devices such as consumer printers, media renderers, and smart appliances.

### 1. Insecurity of Multicast Discovery and Malicious Redirection
SSDP was designed for consumer plug-and-play environments and lacks security controls required for enterprise environments:
* **Unauthenticated Subnet Multicast**: SSDP accepts unauthenticated UDP datagrams from any device on the local network segment. Adversaries can inject spoofed `NOTIFY` announcements advertising rogue network endpoints.
* **Malicious Redirection and SSRF**: When processing SSDP advertisements, Windows parses the packet's `LOCATION` header and initiates an automated HTTP request to download the device's XML schema. An attacker on the local network can coerce the PAW into connecting to an attacker-controlled listener, exposing PAW network addresses and environment signatures.
* **Denial of Service Amplification**: Unhardened SSDP listeners can be weaponized in reflection and amplification attacks across internal networks, consuming bandwidth and system resources.

### 2. PAW Clean Source Integrity and Boundary Protection
Privileged Access Workstations operate under the clean source principle, requiring that administrative systems are isolated from untrusted local network inputs:
* **Strict Boundary Defense**: PAWs must never listen for or process unauthenticated multicast discovery datagrams from local subnets. Operating an open UDP listener on port 1900 on a Tier 0 workstation violates boundary isolation principles.
* **Zero Dependence on Consumer Discovery**: Tier 0 directory administration relies entirely on direct, cryptographically authenticated protocols (WinRM, RPC over Kerberos, HTTPS) directed at managed domain controllers and servers. PAWs have no legitimate interaction with UPnP consumer devices.
* **Attack Surface Reduction**: Disabling the service stops the SSDP parser from executing in the background, eliminating memory corruption vectors in network XML parsers.

### 3. MITRE ATT&CK Mapping
* **T1018 - Remote System Discovery**: Adversaries query SSDP multicast groups to map connected endpoints and administrative hosts.
* **T1557 - Adversary-in-the-Middle**: Spoofing SSDP announcements to coerce outbound network connections.
* **T1498.002 - Network Denial of Service: Reflection Amplification**: Weaponizing SSDP listeners in reflection attacks.

---

## Legacy Impact & Compatibility
* **Tier 0 Administrative Management**: Disabling the SSDP service has zero impact on Active Directory administration, server management tools (RSAT), PowerShell remoting, or Hyper-V administration.
* **Peripherals and Devices**: PAW systems should never connect to unmanaged local subnet consumer peripherals (e.g., smart TVs or wireless streaming dongles). Standard enterprise printers managed through secure print servers function normally.
* **Network Isolation**: The PAW operating system ceases listening on UDP port 1900, reinforcing the workstation's clean source perimeter.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the PAW GPO (e.g., `GPO_Hardening_PAW`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\System Services`
4. Locate `SSDP Discovery` (`SSDPSRV`), double-click to define the policy, and select **Disabled**.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

[Download Script: Configure-DisablePawSSDPSRV.ps1](../implementation_scripts/Configure-DisablePawSSDPSRV.ps1)

```powershell
# Configure-DisablePawSSDPSRV.ps1
# Description: Disables the unnecessary SSDP Discovery (SSDPSRV) service on the local PAW.

Write-Host "Applying hardening requirement: Disable SSDP Discovery service on PAW..." -ForegroundColor Cyan

$ServiceName = "SSDPSRV"
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

[Download Script: Get-PawSSDPSRVStatus.ps1](../audit_scripts/Get-PawSSDPSRVStatus.ps1)

```powershell
# Get-PawSSDPSRVStatus.ps1
# Description: Audits the startup configuration of SSDP Discovery (SSDPSRV) service on the local PAW system.

Write-Host "--- Auditing SSDP Discovery (SSDPSRV) Service on PAW ---" -ForegroundColor Cyan

$ServiceName = "SSDPSRV"
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
* **CIS Microsoft Windows Client Benchmark**: Section 5.32 (SSDPSRV)
* **ANSSI Active Directory Hardening Guide**: Recommendations on limiting active background services on sensitive hosts
* **DoD Windows 11 Computer STIG v2r6**: Unnecessary services restrictions
