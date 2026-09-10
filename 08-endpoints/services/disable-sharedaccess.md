# [REQ-END-039] Disable Internet Connection Sharing (ICS) Service (SharedAccess)

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers. *(For Tier 0 Privileged Access Workstations, refer to tightened baseline [REQ-PAW-039](../../07-paws/services/disable-sharedaccess.md); for Domain Controllers, refer to [REQ-DC-044](../../02-domain-controllers/services/disable-sharedaccess.md)).*
* **Operating Systems**: Windows 10 (all supported editions), Windows 11 Enterprise/Pro, Windows Server 2016, 2019, 2022, and 2025.

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\System Services\Internet Connection Sharing (ICS)` -> **Disabled**
  * **Registry Path**: `HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess`
  * **Value Name**: `Start`
  * **Value Type**: `REG_DWORD`
  * **Value Data**: `4` (Disabled)

---

## Rationale
The Internet Connection Sharing service (`SharedAccess` / ICS) provides Network Address Translation (NAT), dynamic addressing (embedded DHCP server), and name resolution (DNS proxy) capabilities to allow local devices on a network segment to share an external network connection.

### 1. Inherent Threat Vectors and Network Security Compromises
Enabling ICS on enterprise workstations introduces grave network architecture and security risks:
* **Rogue DHCP Server and Traffic Hijacking**: When ICS is engaged, it activates an embedded DHCP daemon that issues IP addresses (typically from `192.168.137.0/24`) and advertises the host as the default gateway and primary DNS server. On an enterprise broadcast domain, an unmanaged DHCP server causes IP address collisions, disrupts legitimate Active Directory DHCP operations, and allows an adversary to execute Adversary-in-the-Middle (AiTM) traffic redirection attacks (MITRE ATT&CK T1557.001).
* **Unauthorized Network Bridging and Perimeter Bypass**: ICS enables users or attackers to bridge an untrusted secondary network interface (such as a 4G/5G mobile cellular modem, USB tethering, or personal Wi-Fi) with the corporate wired LAN. This creates an unmanaged network bridge, allowing untrusted external devices to connect directly into the corporate intranet while bypassing 802.1X Network Access Control (NAC), intrusion detection systems (IDS/IPS), and perimeter security controls (T1200 - Hardware Additions).
* **Covert Egress Channels**: An adversary who compromises a workstation can activate ICS to route traffic across disparate network segments or establish an unauthorized out-of-band egress conduit via an unmonitored cellular adapter.

### 2. Principle of Least Functionality
In enterprise Active Directory environments:
* Network addressing, routing, and DNS resolution must be controlled exclusively by authorized corporate infrastructure.
* Workstations and member servers must never act as NAT routers or DHCP servers. Disabling `SharedAccess` permanently neutralizes unauthorized network bridging and Rogue DHCP hazards across the fleet.

### 3. MITRE ATT&CK Mapping
* **T1557.001 - Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and Rogue DHCP**: Deploying unauthorized DHCP and DNS proxies to capture and manipulate corporate traffic.
* **T1200 - Hardware Additions**: Bridging unauthorized wireless or cellular hardware to bypass perimeter network access controls.
* **T1090 - Proxy**: Leveraging multi-homed ICS routing for lateral movement and covert data exfiltration.

---

## Legacy Impact & Compatibility
* **Corporate Network Operations**: Disabling ICS has zero negative impact on standard corporate network connectivity, DHCP lease renewal from enterprise servers, DNS resolution, or domain authentication.
* **Internet Tethering Restriction**: Users will be unable to share their corporate laptop's network connection with personal mobile phones or guest computers. Enforcing this restriction is a mandatory security control across enterprise environments.
* **Windows Firewall Independence**: Disabling `SharedAccess` does not disable the Windows Defender Firewall. Modern Windows Defender Firewall functionality is hosted in the Windows Defender Firewall service (`mpssvc`), which operates independently.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the target endpoints GPO (e.g., `GPO_Hardening_Endpoints`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\System Services`
4. Locate `Internet Connection Sharing (ICS)` (`SharedAccess`), double-click to define the policy, and select **Disabled**.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

[Download Script: Configure-DisableSharedAccess.ps1](../implementation_scripts/Configure-DisableSharedAccess.ps1)

```powershell
# Configure-DisableSharedAccess.ps1
# Description: Disables the unnecessary Internet Connection Sharing (ICS) (SharedAccess) service.

Write-Host "Applying hardening requirement: Disable Internet Connection Sharing (ICS) service..." -ForegroundColor Cyan

$ServiceName = "SharedAccess"
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

[Download Script: Get-SharedAccessStatus.ps1](../audit_scripts/Get-SharedAccessStatus.ps1)

```powershell
# Get-SharedAccessStatus.ps1
# Description: Audits the startup configuration of Internet Connection Sharing (ICS) (SharedAccess) service.

Write-Host "--- Auditing Internet Connection Sharing (ICS) (SharedAccess) Service ---" -ForegroundColor Cyan

$ServiceName = "SharedAccess"
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
* **CIS Microsoft Windows Client Benchmark**: Section 5.9 (SharedAccess)
* **ANSSI Active Directory Hardening Guide**: Recommendations on host service minimization
* **DoD Windows 11 Computer STIG v2r6**: Unnecessary services restrictions
