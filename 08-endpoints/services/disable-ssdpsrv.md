# [REQ-END-047] Disable SSDP Discovery Service (SSDPSRV)

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers. *(For Tier 0 Privileged Access Workstations, refer to tightened baseline [REQ-PAW-047](../../07-paws/services/disable-ssdpsrv.md); for Domain Controllers, refer to [REQ-DC-060](../../02-domain-controllers/services/disable-ssdpsrv.md)).*
* **Operating Systems**: Windows 10 (all supported editions), Windows 11 Enterprise/Pro, Windows Server 2016, 2019, 2022, and 2025.

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
The Simple Service Discovery Protocol (SSDP) Discovery service (`SSDPSRV`) listens on UDP port 1900 multicast (`239.255.255.250` for IPv4 and `[FF02::C]` / `[FF05::C]` for IPv6) to discover Universal Plug and Play (UPnP) networked devices such as consumer printers, residential gateways, smart displays, and media renderers.

### 1. Architectural Insecurity and Exploitation Vectors
Operating an unauthenticated multicast discovery protocol on enterprise endpoints introduces several distinct attack vectors:
* **Unauthenticated Multicast and Spoofing**: SSDP operates entirely without cryptographic authentication or message integrity validation. Any device on the local network segment can broadcast spoofed `NOTIFY` announcements advertising malicious network services, fake printers, or rogue gateways.
* **Malicious Redirection and Credential Coercion**: When Windows receives an SSDP device announcement, it parses the packet's `LOCATION` header and initiates an outbound HTTP `GET` request to retrieve the device's XML description file. An adversary on the local subnet can broadcast crafted SSDP announcements directing endpoints to an attacker-controlled HTTP server. This enables attackers to map internal IP addresses, fingerprint host environments, execute Server-Side Request Forgery (SSRF), or attempt NTLM credential coercion and relay attacks.
* **Reflection and Amplification Denial of Service**: SSDP `M-SEARCH` queries produce response packets with significant amplification factors (up to 30x). Attackers leverage unhardened SSDP listeners to participate in distributed reflection denial of service attacks across internal subnets.
* **Parser Memory Corruption Vulnerabilities**: The SSDP service processes unvalidated XML documents and HTTP headers received over unencrypted network streams, historically exposing hosts to memory corruption and remote code execution vulnerabilities in system network components.

### 2. Enterprise Baseline and Least Functionality
Enterprise Active Directory environments manage network resources through centralized infrastructure:
* Network printers, scanners, and file repositories are deployed via Group Policy, print servers, and authoritative enterprise DNS records, rendering UPnP device discovery redundant.
* Disabling the SSDP Discovery service eliminates an unauthenticated UDP listener on port 1900, suppresses unnecessary multicast noise on corporate LANs, and blocks rogue device injection.

### 3. MITRE ATT&CK Mapping
* **T1018 - Remote System Discovery**: Adversaries leverage SSDP multicast queries to discover active endpoints, network appliances, and host configurations.
* **T1557 - Adversary-in-the-Middle**: Spoofing SSDP `NOTIFY` announcements to redirect endpoint traffic or coerce outbound authentication.
* **T1498.002 - Network Denial of Service: Reflection Amplification**: Exploiting UDP port 1900 SSDP listeners in reflection attacks.

---

## Legacy Impact & Compatibility
* **Enterprise Printing & Scanning**: Corporate network printers managed via Windows Print Servers, direct IP printing (Standard TCP/IP Port), or modern Web Services on Devices (WSD) with Function Discovery operate normally without the SSDP service.
* **Consumer Media Streaming**: Consumer DLNA media sharing, casting to consumer smart televisions, and UPnP home automation discovery will be disabled. These capabilities are inappropriate for enterprise endpoints.
* **Remote Management**: Core enterprise remote administration protocols (WinRM, RPC/WMI, PowerShell Remoting, SSH) do not utilize SSDP and function without interruption.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the target endpoints GPO (e.g., `GPO_Hardening_Endpoints`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\System Services`
4. Locate `SSDP Discovery` (`SSDPSRV`), double-click to define the policy, and select **Disabled**.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

[Download Script: Configure-DisableSSDPSRV.ps1](../implementation_scripts/Configure-DisableSSDPSRV.ps1)

```powershell
# Configure-DisableSSDPSRV.ps1
# Description: Disables the unnecessary SSDP Discovery (SSDPSRV) service.

Write-Host "Applying hardening requirement: Disable SSDP Discovery service..." -ForegroundColor Cyan

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

*To verify the startup type of this unnecessary service:*

[Download Script: Get-SSDPSRVStatus.ps1](../audit_scripts/Get-SSDPSRVStatus.ps1)

```powershell
# Get-SSDPSRVStatus.ps1
# Description: Audits the startup configuration of SSDP Discovery (SSDPSRV) service.

Write-Host "--- Auditing SSDP Discovery (SSDPSRV) Service ---" -ForegroundColor Cyan

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
* **ANSSI Active Directory Hardening Guide**: Recommendations on host service minimization
* **DoD Windows 11 Computer STIG v2r6**: Unnecessary services restrictions
