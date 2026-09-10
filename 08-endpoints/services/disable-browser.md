# [REQ-END-037] Disable Computer Browser Service (Browser)

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers. *(For Tier 0 Privileged Access Workstations, refer to tightened baseline [REQ-PAW-037](../../07-paws/services/disable-browser.md); for Domain Controllers, refer to [REQ-DC-016](../../02-domain-controllers/disable-smbv1.md)).*
* **Operating Systems**: Windows 10 (all supported editions), Windows 11 Enterprise/Pro, Windows Server 2016, 2019, 2022, and 2025.

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\System Services\Computer Browser` -> **Disabled**
  * **Registry Path**: `HKLM\SYSTEM\CurrentControlSet\Services\Browser`
  * **Value Name**: `Start`
  * **Value Type**: `REG_DWORD`
  * **Value Data**: `4` (Disabled)

---

## Rationale
The Computer Browser service (`Browser`, driven by the legacy kernel driver `bowser.sys`) maintains an inventory of domains, workgroups, and network servers across local network segments using unauthenticated NetBIOS over TCP/IP (NetBT) broadcast frames and Server Message Block version 1 (SMBv1) protocol datagrams.

### 1. Insecurity of NetBIOS Broadcasts and Browser Elections
The Computer Browser architecture dates back to legacy LAN Manager and Windows for Workgroups environments and possesses inherent architectural vulnerabilities:
* **Unauthenticated Broadcast Traffic**: Master browser announcements (`HostAnnouncement`) and election requests (`RequestElection`) are transmitted as cleartext UDP broadcast datagrams over NetBIOS ports 137 and 138. Any host on the local broadcast domain can forge election frames to force master browser elections, demote legitimate master browsers, and claim master browser status.
* **Passive Network Reconnaissance**: By eavesdropping on NetBIOS browser datagrams or querying the elected master browser, an adversary on the subnet can passively enumerate all domain members, file servers, and workstations without generating alertable event logs or establishing direct connections to target endpoints.
* **Driver Vulnerabilities**: The underlying kernel driver `bowser.sys` processes incoming broadcast datagrams in kernel space (ring 0). Historically, vulnerabilities in `bowser.sys` (such as buffer overflows and memory corruption bugs) allowed remote attackers to execute arbitrary code with kernel privileges by transmitting crafted NetBIOS datagrams.

### 2. Dependency on Deprecated SMBv1 Protocol
The Computer Browser service cannot function without the SMBv1 protocol stack:
* Microsoft formally deprecated and removed SMBv1 by default starting with Windows 10 Version 1709 and Windows Server Version 1709 due to critical design flaws (including EternalBlue / MS17-010). Disabling SMBv1 automatically renders the Computer Browser service non-functional.
* Modern enterprise networks rely exclusively on Active Directory Domain Services (AD DS) LDAP queries, Kerberos authentication, and Domain Name System (DNS) for host and service discovery. Leaving the Computer Browser service enabled maintains unnecessary legacy attack surface without providing any functional utility.

### 3. MITRE ATT&CK Mapping
* **T1018 - Remote System Discovery**: Adversaries listen to NetBIOS host announcements or query master browsers to discover live hosts and directory roles.
* **T1557.001 - Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay**: Exploiting broadcast and unauthenticated NetBIOS protocols for credential interception and relay attacks.
* **T1210 - Exploitation of Remote Services**: Exploiting kernel drivers associated with legacy network subsystems.

---

## Legacy Impact & Compatibility
* **Active Directory Domain Operations**: Disabling the Computer Browser service has zero impact on Active Directory domain join, Kerberos authentication, Group Policy processing, DNS resolution, or standard SMB file share access.
* **Network Neighborhood Browsing**: Systems with the Computer Browser service disabled will not participate in legacy "Network Neighborhood" workgroup lists. Modern local device discovery relies on Web Services Dynamic Discovery (WS-Discovery) and Function Discovery (`FDPHost` / `FDResPub`), which operate independently of the Computer Browser service.
* **Legacy Appliances**: Non-domain embedded devices manufactured prior to 2008 that strictly depend on NetBIOS master browsing will not see Windows endpoints in legacy browse lists. Direct UNC access via FQDN or IP address (e.g., `\\server.domain.local\share`) remains fully supported using modern SMB 2.x and 3.x protocols.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the target endpoints GPO (e.g., `GPO_Hardening_Endpoints`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\System Services`
4. Locate `Computer Browser` (`Browser`), double-click to define the policy, and select **Disabled**.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

[Download Script: Configure-DisableBrowser.ps1](../implementation_scripts/Configure-DisableBrowser.ps1)

```powershell
# Configure-DisableBrowser.ps1
# Description: Disables the unnecessary Computer Browser (Browser) service.

Write-Host "Applying hardening requirement: Disable Computer Browser service..." -ForegroundColor Cyan

$ServiceName = "Browser"
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

[Download Script: Get-BrowserStatus.ps1](../audit_scripts/Get-BrowserStatus.ps1)

```powershell
# Get-BrowserStatus.ps1
# Description: Audits the startup configuration of Computer Browser (Browser) service.

Write-Host "--- Auditing Computer Browser (Browser) Service ---" -ForegroundColor Cyan

$ServiceName = "Browser"
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
* **CIS Microsoft Windows Client Benchmark**: Section 5.3 (Browser)
* **ANSSI Active Directory Hardening Guide**: Recommendations on host service minimization
* **DoD Windows 11 Computer STIG v2r6**: Unnecessary services restrictions
