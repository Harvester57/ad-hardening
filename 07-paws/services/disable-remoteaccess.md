# [REQ-PAW-044] Disable Routing and Remote Access Service for PAWs (RemoteAccess)

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration. *(For standard client workstations and member servers, refer to baseline [REQ-END-044](../../08-endpoints/services/disable-remoteaccess.md)).*
* **Operating Systems**: Windows 10 Enterprise (all supported builds) and Windows 11 Enterprise.

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
The Routing and Remote Access Service (`RemoteAccess` / RRAS) provides software-based packet routing, Network Address Translation (NAT), and incoming VPN server termination capabilities.

### 1. Inherent Threat of Routing Services on Administrative Endpoints
Enabling packet routing or VPN hosting capabilities on a dedicated administrative endpoint presents fatal security vulnerabilities:
* **Multi-Interface Bridging**: An adversary compromising a PAW could configure RRAS to route network packets between network interfaces (e.g., bridging a dedicated Tier 0 VLAN with a secondary Wi-Fi or cellular interface). This would destroy Tier 0 boundary containment, allowing unauthorized traffic to flow between unmanaged subnets and mission-critical directory services (MITRE ATT&CK T1090 - Proxy, T1572 - Protocol Tunneling).
* **Rogue Remote Access Gateway**: RRAS allows the host to act as an incoming VPN gateway or dial-in server. An adversary could leverage RRAS to establish an unauthorized ingress channel directly into the administrative enclave, circumventing boundary firewalls and perimeter monitoring.

### 2. PAW Clean Source and Single-Homing Boundary Enforcement
Privileged Access Workstations must comply with the clean source principle and strict network boundary restrictions:
* **Single-Homing Principle**: PAWs must be strictly single-homed into dedicated, secured management VLANs. Multi-interface bridging, packet forwarding, and software-based routing are strictly forbidden on administrative workstations.
* **Unidirectional Administrative Workflows**: PAW network communication is strictly outbound toward managed Tier 0 targets (Domain Controllers, PKI/CAs, Tier 0 hypervisors). PAWs must never accept inbound transit traffic, act as intermediate routers, or terminate incoming remote access tunnels.
* **Subsystem Minimization**: Disabling RRAS ensures the operating system kernel cannot be instructed to forward IP datagrams between network interfaces, preventing lateral pivoting and network boundary bypasses.

### 3. MITRE ATT&CK Mapping
* **T1090 - Proxy**: Configuring routing services to proxy and route adversary traffic between segmented network enclaves.
* **T1572 - Protocol Tunneling**: Abusing software routing and VPN encapsulation to bypass perimeter boundary controls.
* **T1133 - External Remote Services**: Hosting unauthorized inbound remote access servers on administrative workstations.

---

## Legacy Impact & Compatibility
* **Tier 0 Administrative Management**: Disabling RRAS has zero impact on Active Directory administration, server management tools (RSAT), PowerShell remoting, or Hyper-V administration.
* **Outbound Management VPNs**: If PAWs utilize a dedicated, isolated administrative VPN to reach remote Tier 0 data centers, client-side VPN connectivity is handled by the Remote Access Connection Manager (`RasMan`), which functions independently of the `RemoteAccess` server service.
* **Boundary Integrity**: Enforces strict single-network host isolation, ensuring the PAW can never be weaponized as an unauthorized bridge into Tier 0 infrastructure.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the PAW GPO (e.g., `GPO_Hardening_PAW`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\System Services`
4. Locate `Routing and Remote Access` (`RemoteAccess`), double-click to define the policy, and select **Disabled**.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

[Download Script: Configure-DisablePawRemoteAccess.ps1](../implementation_scripts/Configure-DisablePawRemoteAccess.ps1)

```powershell
# Configure-DisablePawRemoteAccess.ps1
# Description: Disables the unnecessary Routing and Remote Access (RemoteAccess) service on the local PAW.

Write-Host "Applying hardening requirement: Disable Routing and Remote Access service on PAW..." -ForegroundColor Cyan

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

*To verify the startup type of this unnecessary service on the PAW:*

[Download Script: Get-PawRemoteAccessStatus.ps1](../audit_scripts/Get-PawRemoteAccessStatus.ps1)

```powershell
# Get-PawRemoteAccessStatus.ps1
# Description: Audits the startup configuration of Routing and Remote Access (RemoteAccess) service on the local PAW system.

Write-Host "--- Auditing Routing and Remote Access (RemoteAccess) Service on PAW ---" -ForegroundColor Cyan

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
* **ANSSI Active Directory Hardening Guide**: Recommendations on limiting active background services on sensitive hosts
* **DoD Windows 11 Computer STIG v2r6**: Unnecessary services restrictions
