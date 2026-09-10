# [REQ-PAW-050] Disable Windows Media Player Network Sharing Service for PAWs (WMPNetworkSvc)

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration. *(For Tier 2 client workstations and member servers, refer to baseline [REQ-END-050](../../08-endpoints/services/disable-wmpnetworksvc.md)).*
* **Operating Systems**: Windows 10 Enterprise (1607+) and Windows 11 Enterprise.

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
The Windows Media Player Network Sharing Service (`WMPNetworkSvc`, hosted by `wmpnetwk.exe` or `svchost.exe`) shares local Windows Media Player multimedia libraries across the network using Universal Plug and Play (UPnP) and Digital Living Network Alliance (DLNA) protocols.

### 1. Enforcement of the Clean Source Principle and Zero Inbound Listeners
Under Microsoft Privileged Access Workstation guidelines and the Clean Source Principle, Tier 0 administrative workstations must be hardened to the highest standard:
* **Elimination of Inbound Listening Sockets**: A PAW must strictly avoid running unauthenticated inbound network listeners. When enabled, `WMPNetworkSvc` binds to TCP port 2869 (UPnP eventing/HTTP), TCP port 10243 (WMP HTTP streaming), and listens for SSDP multicast datagrams on UDP port 1900.
* **Isolation from Lateral Movement**: Inbound network daemons on a PAW present a high-risk lateral traversal vector. An adversary who compromises a Tier 1 or Tier 2 asset on the same administrative subnet could target the UPnP/DLNA HTTP service on the PAW to achieve remote code execution or local privilege escalation, directly compromising Tier 0 administrative credentials held in LSASS memory.

### 2. Elimination of Multimedia and XML Parsing Attack Surface
* `WMPNetworkSvc` parses untrusted XML device descriptors, SOAP requests, and complex multimedia file container headers (MP3, WMA, MP4, ASF).
* Multimedia parsers have a well-documented history of critical memory corruption and remote code execution vulnerabilities (e.g., CVE-2012-0003 / MS12-005). Executing multimedia parsing code within privileged administrative hosts introduces unnecessary exploit surface into the highest trust zone of the Active Directory forest.

### 3. Absolute Least Functionality on Tier 0 Assets
* Privileged Access Workstations exist exclusively to execute remote administration tools (such as RSAT, PowerShell Remoting, and Windows Admin Center) targeting Domain Controllers and Tier 0 identity infrastructure.
* Multimedia streaming and consumer entertainment protocols serve no legitimate administrative purpose and violate the principle of least functionality.

### 4. MITRE ATT&CK Mapping
* **T1046 - Network Service Discovery**: Attackers scanning internal administrative subnets for listening UPnP/DLNA ports (TCP 2869, 10243) or SSDP beacons (UDP 1900).
* **T1210 - Exploitation of Remote Services**: Leveraging memory corruption vulnerabilities in media streaming network daemons to execute code on Tier 0 workstations.
* **T1082 - System Information Discovery**: Querying DLNA endpoints to enumerate administrative hostnames and profile paths.

---

## Legacy Impact & Compatibility
* **Administrative Operations**: Disabling `WMPNetworkSvc` is completely transparent to all Tier 0 management activities, including RSAT, PowerShell Remoting, Active Directory Administrative Center, Group Policy Management, and Hyper-V/ESXi management consoles.
* **Local Media Playback**: System sound effects and local playback of administrative audio/video recordings remain fully functional. Only unauthenticated network streaming to external DLNA devices is disabled.
* **Compatibility Exception**: There are zero legitimate enterprise or administrative dependencies on Windows Media Player network sharing on Privileged Access Workstations.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the PAW GPO (e.g., `GPO_Hardening_PAW`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\System Services`
4. Locate `Windows Media Player Network Sharing Service` (`WMPNetworkSvc`), double-click to define the policy, and select **Disabled**.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

[Download Script: Configure-DisablePawWMPNetworkSvc.ps1](../implementation_scripts/Configure-DisablePawWMPNetworkSvc.ps1)

```powershell
# Configure-DisablePawWMPNetworkSvc.ps1
# Description: Disables the unnecessary Windows Media Player Network Sharing Service (WMPNetworkSvc) service on the local PAW.

Write-Host "Applying hardening requirement: Disable Windows Media Player Network Sharing Service service on PAW..." -ForegroundColor Cyan

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

*To verify the startup type of this unnecessary service on the PAW:*

[Download Script: Get-PawWMPNetworkSvcStatus.ps1](../audit_scripts/Get-PawWMPNetworkSvcStatus.ps1)

```powershell
# Get-PawWMPNetworkSvcStatus.ps1
# Description: Audits the startup configuration of Windows Media Player Network Sharing Service (WMPNetworkSvc) service on the local PAW system.

Write-Host "--- Auditing Windows Media Player Network Sharing Service (WMPNetworkSvc) Service on PAW ---" -ForegroundColor Cyan

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
* **ANSSI Active Directory Hardening Guide**: Recommendations on limiting active background services on sensitive hosts
* **DoD Windows 11 Computer STIG v2r6**: Unnecessary services restrictions
