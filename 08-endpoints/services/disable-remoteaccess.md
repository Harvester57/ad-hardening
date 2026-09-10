# [REQ-END-044] Disable Routing and Remote Access Service (RemoteAccess)

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers. *(For Tier 0 Privileged Access Workstations, refer to tightened baseline [REQ-PAW-044](../../07-paws/services/disable-remoteaccess.md)).*
* **Operating Systems**: Windows 10 (all supported editions), Windows 11 Enterprise/Pro, Windows Server 2016, 2019, 2022, and 2025.

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\System Services\Routing and Remote Access` -> **Disabled**
  * **Registry Path**: `HKLM\SYSTEM\CurrentControlSet\Services\RemoteAccess`
  * **Value Name**: `Start`
  * **Value Type**: `REG_DWORD`
  * **Value Data**: `4` (Disabled)

---

## Rationale
The Routing and Remote Access Service (`RemoteAccess` / RRAS) provides multi-protocol LAN-to-LAN routing, Network Address Translation (NAT), dial-up networking, and VPN server capabilities (PPTP, L2TP, SSTP, IKEv2).

### 1. Network Segmentation Bypasses and Unauthorized Pivoting
Enabling routing capabilities on enterprise client endpoints presents critical architectural risks:
* **Unauthorized Multi-Interface Routing**: If an endpoint is multi-homed (e.g., connected simultaneously to an enterprise corporate LAN and a secondary Wi-Fi, cellular, or VPN adapter), an adversary with local administrative access can enable RRAS to route IP packets between interfaces. This allows the adversary to bypass perimeter firewalls, bridge isolated network segments, and access internal enclaves without traversing monitored network gateways (MITRE ATT&CK T1090 - Proxy, T1572 - Protocol Tunneling).
* **Rogue Remote Access Ingress**: RRAS allows the host to act as a VPN or dial-in server. Malicious actors or unauthorized users can configure RRAS to host an unauthorized inbound VPN endpoint, establishing persistent external backdoor access directly into the corporate LAN.
* **Legacy Protocol Vulnerabilities**: RRAS includes support for obsolete and cryptographically insecure tunneling protocols, such as PPTP with MS-CHAPv2 authentication, which are vulnerable to credential cracking, spoofing, and man-in-the-middle attacks.

### 2. Principle of Least Functionality and Role Demarcation
In an enterprise network architecture:
* Routing, NAT, and remote access termination are strictly the responsibility of enterprise perimeter firewalls, routers, and dedicated VPN concentrators.
* Workstations and standard member servers must operate solely as endpoint nodes and must never route transit traffic. Disabling RRAS ensures that hosts cannot be repurposed as unauthorized network routers or covert transit hops.

### 3. MITRE ATT&CK Mapping
* **T1090 - Proxy**: Configuring routing services to proxy and relay traffic between segmented networks.
* **T1572 - Protocol Tunneling**: Abusing VPN and routing protocols to circumvent boundary security controls.
* **T1133 - External Remote Services**: Hosting unauthorized inbound remote access endpoints on enterprise hosts.

---

## Legacy Impact & Compatibility
* **Outbound Enterprise VPN Clients**: Disabling the `RemoteAccess` service does **not** prevent endpoints from connecting as clients to corporate VPN concentrators (e.g., Windows Always On VPN, Cisco AnyConnect, Palo Alto GlobalProtect). Outbound client VPN connections are managed by the Remote Access Connection Manager (`RasMan`), which functions independently.
* **Network Operations**: Standard TCP/IP networking, DHCP lease acquisition, DNS resolution, and domain authentication operate normally.
* **Dedicated Gateway Servers**: If a specialized Windows Server is intentionally deployed as an edge NAT router or DirectAccess server, that machine must be placed in a dedicated Organizational Unit (OU) with an explicit policy exception. All standard workstations and member servers must have RRAS disabled.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the target endpoints GPO (e.g., `GPO_Hardening_Endpoints`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\System Services`
4. Locate `Routing and Remote Access` (`RemoteAccess`), double-click to define the policy, and select **Disabled**.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

[Download Script: Configure-DisableRemoteAccess.ps1](../implementation_scripts/Configure-DisableRemoteAccess.ps1)

```powershell
# Configure-DisableRemoteAccess.ps1
# Description: Disables the unnecessary Routing and Remote Access (RemoteAccess) service.

Write-Host "Applying hardening requirement: Disable Routing and Remote Access service..." -ForegroundColor Cyan

$ServiceName = "RemoteAccess"
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

[Download Script: Get-RemoteAccessStatus.ps1](../audit_scripts/Get-RemoteAccessStatus.ps1)

```powershell
# Get-RemoteAccessStatus.ps1
# Description: Audits the startup configuration of Routing and Remote Access (RemoteAccess) service.

Write-Host "--- Auditing Routing and Remote Access (RemoteAccess) Service ---" -ForegroundColor Cyan

$ServiceName = "RemoteAccess"
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
* **CIS Microsoft Windows Client Benchmark**: Section 5.27 (RemoteAccess)
* **ANSSI Active Directory Hardening Guide**: Recommendations on host service minimization
* **DoD Windows 11 Computer STIG v2r6**: Unnecessary services restrictions
