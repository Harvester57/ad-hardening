# [REQ-PAW-037] Disable Computer Browser Service for PAWs (Browser)

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration. *(For standard client workstations and member servers, refer to baseline [REQ-END-037](../../08-endpoints/services/disable-browser.md); for Domain Controllers, refer to [REQ-DC-016](../../02-domain-controllers/disable-smbv1.md)).*
* **Operating Systems**: Windows 10 Enterprise (all supported builds) and Windows 11 Enterprise.

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
The Computer Browser service (`Browser`, driven by the kernel driver `bowser.sys`) maintains an inventory of network servers and domains across local network segments using unauthenticated NetBIOS over TCP/IP (NetBT) broadcast frames and legacy Server Message Block version 1 (SMBv1) protocol datagrams.

### 1. Insecurity of NetBIOS Broadcasts and Browser Elections
The Computer Browser architecture relies on legacy broadcast protocols that present serious security vulnerabilities:
* **Unauthenticated Broadcast Traffic**: Master browser announcements (`HostAnnouncement`) and election requests (`RequestElection`) are transmitted as cleartext UDP datagrams across local broadcast domains (ports 137 and 138). Any host on the subnet can inject spoofed election frames to claim master browser status, force browser elections, or poison browse lists.
* **Subnet Reconnaissance**: Attackers monitoring NetBIOS broadcast traffic can map internal hostnames, workgroups, and server roles without generating security alerts or establishing direct connections to endpoints.
* **Kernel Attack Surface**: The underlying driver `bowser.sys` runs in kernel space (ring 0) to parse incoming broadcast datagrams. Historically, vulnerabilities in `bowser.sys` (including buffer overflows and memory corruption flaws) allowed remote attackers to execute arbitrary code with kernel privileges by transmitting crafted NetBIOS frames.

### 2. PAW Clean Source and Strict Isolation Requirements
Privileged Access Workstations represent the most sensitive endpoints in the enterprise, providing administrative access to Tier 0 directory infrastructure:
* **Clean Source Principle**: PAWs must operate strictly under the clean source principle, eliminating all unauthenticated peer-to-peer listeners and broadcast protocols that could expose the workstation to untrusted subnet traffic.
* **Direct Point-to-Point Management**: Tier 0 administrative operations (using RSAT, PowerShell remoting, and Active Directory management consoles) rely exclusively on DNS name resolution, Kerberos authentication, and secure point-to-point protocols (such as WinRM/HTTPS and RPC/Kerberos). PAWs have no legitimate requirement to participate in local NetBIOS network discovery or maintain legacy SMBv1-dependent browser services.
* **Driver Minimization**: Disabling the service prevents `bowser.sys` from loading into kernel memory, closing a potential local privilege escalation and remote code execution vector.

### 3. MITRE ATT&CK Mapping
* **T1018 - Remote System Discovery**: Adversaries eavesdrop on NetBIOS broadcasts or query master browsers to identify enterprise assets and administrative endpoints.
* **T1557.001 - Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay**: Exploiting broadcast and unauthenticated NetBIOS protocols for credential interception and relay attacks.
* **T1210 - Exploitation of Remote Services**: Exploiting kernel drivers associated with legacy network subsystems.

---

## Legacy Impact & Compatibility
* **Tier 0 Administrative Operations**: Disabling the Computer Browser service has zero impact on Active Directory administration, remote server management (RSAT), PowerShell remoting, or Hyper-V/cluster management.
* **Network Isolation**: Windows Explorer on the PAW will not display workgroup browse lists. This is the desired security posture for administrative hosts, which should never interact with unmanaged local peer systems.
* **Modern Name Resolution**: PAWs continue to resolve domain hosts and services via authoritative enterprise DNS servers over encrypted or authenticated channels.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the PAW GPO (e.g., `GPO_Hardening_PAW`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\System Services`
4. Locate `Computer Browser` (`Browser`), double-click to define the policy, and select **Disabled**.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

[Download Script: Configure-DisablePawBrowser.ps1](../implementation_scripts/Configure-DisablePawBrowser.ps1)

```powershell
# Configure-DisablePawBrowser.ps1
# Description: Disables the unnecessary Computer Browser (Browser) service on the local PAW.

Write-Host "Applying hardening requirement: Disable Computer Browser service on PAW..." -ForegroundColor Cyan

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

*To verify the startup type of this unnecessary service on the PAW:*

[Download Script: Get-PawBrowserStatus.ps1](../audit_scripts/Get-PawBrowserStatus.ps1)

```powershell
# Get-PawBrowserStatus.ps1
# Description: Audits the startup configuration of Computer Browser (Browser) service on the local PAW system.

Write-Host "--- Auditing Computer Browser (Browser) Service on PAW ---" -ForegroundColor Cyan

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
* **ANSSI Active Directory Hardening Guide**: Recommendations on limiting active background services on sensitive hosts
* **DoD Windows 11 Computer STIG v2r6**: Unnecessary services restrictions
