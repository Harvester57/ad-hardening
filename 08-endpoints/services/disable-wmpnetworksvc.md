# [REQ-END-050] Disable Windows Media Player Network Sharing Service (WMPNetworkSvc)

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers. *(For Tier 0 Privileged Access Workstations, refer to tightened baseline [REQ-PAW-050](../../07-paws/services/disable-wmpnetworksvc.md)).*
* **Operating Systems**: Windows 10 (all supported editions), Windows 11 Enterprise/Pro, Windows Server 2016, 2019, 2022, and 2025.

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\System Services\Windows Media Player Network Sharing Service` -> **Disabled**
  * **Registry Path**: `HKLM\SYSTEM\CurrentControlSet\Services\WMPNetworkSvc`
  * **Value Name**: `Start`
  * **Value Type**: `REG_DWORD`
  * **Value Data**: `4` (Disabled)

---

## Rationale
The Windows Media Player Network Sharing Service (`WMPNetworkSvc`, hosted by `wmpnetwk.exe` or `svchost.exe`) shares Windows Media Player multimedia libraries (audio, video, playlists) with other network media players and control devices over Universal Plug and Play (UPnP) and Digital Living Network Alliance (DLNA) protocols.

### 1. Unauthenticated Remote Media Streaming and Listening Sockets
When active, `WMPNetworkSvc` binds to local network interfaces and exposes multiple unauthenticated listening sockets:
* **HTTP and UPnP Eventing Listeners**: Listens on TCP port 2869 (UPnP eventing/HTTP) and TCP port 10243 (WMP media sharing HTTP listener) to serve media content and metadata via HTTP GET/POST requests.
* **SSDP Multicast Announcements**: Sends and receives Simple Service Discovery Protocol (SSDP) datagrams over UDP port 1900 to announce media availability across the local broadcast domain.
* **Passive Reconnaissance and Information Disclosure**: Any host on the local network segment can query the DLNA endpoints without authentication. This allows unauthorized actors to enumerate media file metadata, system hostnames, user profile paths, and directory names embedded in media index databases.

### 2. Multimedia Parser Attack Surface and Remote Exploitation
Handling media libraries involves parsing complex file formats and untrusted network XML descriptions:
* **Complex Media Format Parsing**: The service indexes and streams formats such as MP3, WMA, WMV, and MP4. Complex multimedia container parsers have historically suffered from integer overflows, heap corruptions, and remote code execution vulnerabilities (e.g., CVE-2012-0003 / MS12-005).
* **UPnP/SOAP XML Parsing**: The service processes untrusted XML and SOAP payloads sent by remote UPnP control points. Vulnerabilities in XML parsers can lead to denial-of-service, memory disclosure, or server-side request forgery (SSRF).

### 3. Least Functionality in Enterprise Environments
Enterprise client workstations and member servers have no legitimate operational need to function as DLNA media servers:
* Operating multimedia streaming services violates the principle of least functionality (NIST SP 800-53 CM-7).
* Disabling the service closes unnecessary inbound listening ports (TCP 2869, TCP 10243), suppresses SSDP multicast discovery traffic, and removes a persistent background process.

### 4. MITRE ATT&CK Mapping
* **T1046 - Network Service Discovery**: Adversaries scan for listening UPnP/DLNA ports (TCP 2869, 10243) or listen for SSDP announcements (UDP 1900) to identify active endpoints.
* **T1210 - Exploitation of Remote Services**: Exploiting vulnerabilities in media streaming network daemons or XML parsers for remote code execution.
* **T1082 - System Information Discovery**: Querying DLNA metadata endpoints to harvest host identifiers and user folder structures.

---

## Legacy Impact & Compatibility
* **Enterprise Operations**: Disabling `WMPNetworkSvc` is completely transparent to Active Directory domain operations, Kerberos authentication, SMB file shares, Group Policy processing, and enterprise collaboration applications.
* **Local Media Playback**: Local playback of audio and video files using Windows Media Player, Movies & TV, or third-party enterprise media players is completely unaffected. Only network-based DLNA/UPnP streaming to remote devices is prevented.
* **Network Media Renderers**: Consumer DLNA devices (such as smart TVs or game consoles on the local network) will not be able to discover or stream media libraries hosted on the Windows endpoint.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the target endpoints GPO (e.g., `GPO_Hardening_Endpoints`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\System Services`
4. Locate `Windows Media Player Network Sharing Service` (`WMPNetworkSvc`), double-click to define the policy, and select **Disabled**.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

[Download Script: Configure-DisableWMPNetworkSvc.ps1](../implementation_scripts/Configure-DisableWMPNetworkSvc.ps1)

```powershell
# Configure-DisableWMPNetworkSvc.ps1
# Description: Disables the unnecessary Windows Media Player Network Sharing Service (WMPNetworkSvc) service.

Write-Host "Applying hardening requirement: Disable Windows Media Player Network Sharing Service service..." -ForegroundColor Cyan

$ServiceName = "WMPNetworkSvc"
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

[Download Script: Get-WMPNetworkSvcStatus.ps1](../audit_scripts/Get-WMPNetworkSvcStatus.ps1)

```powershell
# Get-WMPNetworkSvcStatus.ps1
# Description: Audits the startup configuration of Windows Media Player Network Sharing Service (WMPNetworkSvc) service.

Write-Host "--- Auditing Windows Media Player Network Sharing Service (WMPNetworkSvc) Service ---" -ForegroundColor Cyan

$ServiceName = "WMPNetworkSvc"
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
* **CIS Microsoft Windows Client Benchmark**: Section 5.37 (WMPNetworkSvc)
* **ANSSI Active Directory Hardening Guide**: Recommendations on host service minimization
* **DoD Windows 11 Computer STIG v2r6**: Unnecessary services restrictions
