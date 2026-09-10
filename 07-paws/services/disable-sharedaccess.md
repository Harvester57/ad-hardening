# [REQ-PAW-039] Disable Internet Connection Sharing (ICS) Service for PAWs (SharedAccess)

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration. *(For standard client workstations and member servers, refer to baseline [REQ-END-039](../../08-endpoints/services/disable-sharedaccess.md); for Domain Controllers, refer to [REQ-DC-044](../../02-domain-controllers/services/disable-sharedaccess.md)).*
* **Operating Systems**: Windows 10 Enterprise (all supported builds) and Windows 11 Enterprise.

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
The Internet Connection Sharing service (`SharedAccess` / ICS) provides Network Address Translation (NAT), dynamic addressing (embedded DHCP server), and name resolution (DNS proxy) capabilities.

### 1. Severe Network Bridging and Boundary Breakdown on PAWs
Activating ICS on a Privileged Access Workstation creates catastrophic security boundary breaches:
* **Tier 0 Perimeter Destruction**: PAWs are dedicated endpoints reserved exclusively for Tier 0 directory and identity management. Enabling ICS allows the PAW to bridge a secondary network adapter (such as a tethered smartphone, cellular dongle, or wireless NIC) with the secured Tier 0 management subnet. This provides external, untrusted devices with unmonitored Layer 3 routing directly into the most sensitive directory assets (MITRE ATT&CK T1200 - Hardware Additions, T1090 - Proxy).
* **Rogue Network Services Hazard**: The ICS embedded DHCP server binds to local interfaces and issues private IP leases while intercepting DNS requests. On an administrative subnet, unauthorized DHCP daemons disrupt domain controller communication and expose administrative sessions to Adversary-in-the-Middle (AiTM) manipulation (T1557.001).

### 2. Clean Source Principle and Infrastructure Isolation
Under Microsoft's Privileged Access Workstation architecture:
* **Strict Single-Homing**: PAWs must be strictly single-homed into isolated management VLANs protected by 802.1X and strict access control lists (ACLs). Workstations must never execute network routing, NAT, or DHCP services.
* **Credential Isolation**: Any mechanism that allows network transit across a PAW exposes the host to credential compromise. An adversary leveraging an ICS bridge could target the local LSASS process to harvest Tier 0 Domain Admin credentials.
* **Disabling `SharedAccess`**: Disabling this service permanently removes the embedded NAT router, DHCP server, and DNS proxy from the operating system, guaranteeing network isolation.

### 3. MITRE ATT&CK Mapping
* **T1557.001 - Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and Rogue DHCP**: Unauthorized DHCP services deployed to intercept administrative traffic.
* **T1200 - Hardware Additions**: Bridging unauthorized peripheral network devices to bypass physical and network access controls.
* **T1090 - Proxy**: Adversary routing of traffic across network enclaves via compromised multi-homed hosts.

---

## Legacy Impact & Compatibility
* **Tier 0 Administrative Management**: Disabling ICS has zero impact on Active Directory administration, server management tools (RSAT), PowerShell remoting, or Hyper-V administration.
* **Device Tethering Prohibition**: PAW policies strictly prohibit connecting unauthorized cellular devices or establishing ad-hoc network shares.
* **Firewall Continuity**: The core Windows Defender Firewall operates independently under the `mpssvc` service and continues enforcing administrative boundary rules without interruption.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the PAW GPO (e.g., `GPO_Hardening_PAW`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\System Services`
4. Locate `Internet Connection Sharing (ICS)` (`SharedAccess`), double-click to define the policy, and select **Disabled**.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

[Download Script: Configure-DisablePawSharedAccess.ps1](../implementation_scripts/Configure-DisablePawSharedAccess.ps1)

```powershell
# Configure-DisablePawSharedAccess.ps1
# Description: Disables the unnecessary Internet Connection Sharing (ICS) (SharedAccess) service on the local PAW.

Write-Host "Applying hardening requirement: Disable Internet Connection Sharing (ICS) service on PAW..." -ForegroundColor Cyan

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

*To verify the startup type of this unnecessary service on the PAW:*

[Download Script: Get-PawSharedAccessStatus.ps1](../audit_scripts/Get-PawSharedAccessStatus.ps1)

```powershell
# Get-PawSharedAccessStatus.ps1
# Description: Audits the startup configuration of Internet Connection Sharing (ICS) (SharedAccess) service on the local PAW system.

Write-Host "--- Auditing Internet Connection Sharing (ICS) (SharedAccess) Service on PAW ---" -ForegroundColor Cyan

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
* **ANSSI Active Directory Hardening Guide**: Recommendations on limiting active background services on sensitive hosts
* **DoD Windows 11 Computer STIG v2r6**: Unnecessary services restrictions
