# [REQ-END-051] Disable Windows Mobile Hotspot Service (icssvc)

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers. *(For Tier 0 Privileged Access Workstations, refer to tightened baseline [REQ-PAW-051](../../07-paws/services/disable-icssvc.md); for Domain Controllers, refer to [REQ-DC-072](../../02-domain-controllers/services/disable-icssvc.md)).*
* **Operating Systems**: Windows 10 (all supported editions), Windows 11 Enterprise/Pro, Windows Server 2016, 2019, 2022, and 2025.

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\System Services\Windows Mobile Hotspot Service` -> **Disabled**
  * **Registry Path**: `HKLM\SYSTEM\CurrentControlSet\Services\icssvc`
  * **Value Name**: `Start`
  * **Value Type**: `REG_DWORD`
  * **Value Data**: `4` (Disabled)

---

## Rationale
The Windows Mobile Hotspot Service (`icssvc`) manages software-based wireless access points (SoftAP) and connection tethering features, allowing an endpoint to share its Ethernet, Wi-Fi, or cellular connection with external wireless devices.

### 1. Shadow Wireless Networks and Perimeter Access Evasion
Enabling mobile hotspot capabilities on enterprise endpoints introduces critical physical and logical security risks:
* **Rogue Wireless Access Points (SoftAP)**: When activated, `icssvc` creates a local software access point, broadcasting an unmanaged Wi-Fi SSID. This shadow wireless network operates outside the visibility of enterprise Wireless Intrusion Prevention Systems (WIPS), security event logs, and centralized firewall monitoring.
* **Bypassing 802.1X Network Access Control (NAC)**: External, unmanaged devices (such as personal smartphones, unauthorized tablets, or adversary machines within radio range) can associate with the mobile hotspot. Because the host laptop is already authenticated to the corporate LAN via 802.1X/EAP, the host routes and NATs packets from rogue devices directly into the corporate intranet, bypassing perimeter access controls (MITRE ATT&CK T1200 - Hardware Additions).
* **Physical Proximity Exploitation**: Adversaries operating in physical proximity to the facility can target mobile hotspots configured with weak pre-shared keys, compromise the wireless stream, and leverage the connected laptop as an internal network pivot (T1049 - System Network Connections Discovery).

### 2. Least Functionality in Enterprise Environments
In a hardened corporate fleet:
* Workstations must function strictly as clients connected to managed corporate access points or wired switch ports.
* Disabling `icssvc` ensures that workstations cannot broadcast unauthorized Wi-Fi beacons, bridge foreign devices onto corporate subnets, or act as rogue wireless gateways.

### 3. MITRE ATT&CK Mapping
* **T1200 - Hardware Additions**: Creating rogue wireless SoftAP access points to connect unvetted hardware into enterprise networks.
* **T1049 - System Network Connections Discovery**: Identifying and abusing multi-homed network connections to bridge disparate subnets.
* **T1557 - Adversary-in-the-Middle**: Capturing or relaying network communications across ad-hoc wireless connections.

---

## Legacy Impact & Compatibility
* **Corporate Wi-Fi Client Connections**: Disabling `icssvc` does **not** impact an endpoint's ability to connect as a client to corporate Wi-Fi networks. Client wireless connectivity is managed by WLAN AutoConfig (`WlanSvc`), which operates independently.
* **Mobile Hotspot Restriction**: The "Mobile hotspot" toggle in Windows Settings will be disabled. Users cannot share corporate internet connections with personal devices.
* **Enterprise Operations**: Standard domain services, Group Policy processing, VPN connections, and line-of-business applications operate without interruption.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the target endpoints GPO (e.g., `GPO_Hardening_Endpoints`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\System Services`
4. Locate `Windows Mobile Hotspot Service` (`icssvc`), double-click to define the policy, and select **Disabled**.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

[Download Script: Configure-Disableicssvc.ps1](../implementation_scripts/Configure-Disableicssvc.ps1)

```powershell
# Configure-Disableicssvc.ps1
# Description: Disables the unnecessary Windows Mobile Hotspot Service (icssvc) service.

Write-Host "Applying hardening requirement: Disable Windows Mobile Hotspot Service service..." -ForegroundColor Cyan

$ServiceName = "icssvc"
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

[Download Script: Get-icssvcStatus.ps1](../audit_scripts/Get-icssvcStatus.ps1)

```powershell
# Get-icssvcStatus.ps1
# Description: Audits the startup configuration of Windows Mobile Hotspot Service (icssvc) service.

Write-Host "--- Auditing Windows Mobile Hotspot Service (icssvc) Service ---" -ForegroundColor Cyan

$ServiceName = "icssvc"
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
* **CIS Microsoft Windows Client Benchmark**: Section 5.38 (icssvc)
* **ANSSI Active Directory Hardening Guide**: Recommendations on host service minimization
* **DoD Windows 11 Computer STIG v2r6**: Unnecessary services restrictions
