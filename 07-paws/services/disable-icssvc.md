# [REQ-PAW-051] Disable Windows Mobile Hotspot Service for PAWs (icssvc)

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration. *(For standard client workstations and member servers, refer to baseline [REQ-END-051](../../08-endpoints/services/disable-icssvc.md); for Domain Controllers, refer to [REQ-DC-072](../../02-domain-controllers/services/disable-icssvc.md)).*
* **Operating Systems**: Windows 10 Enterprise (all supported builds) and Windows 11 Enterprise.

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
The Windows Mobile Hotspot Service (`icssvc`) manages software-based wireless access point (SoftAP) hosting and network tethering features.

### 1. Catastrophic Boundary Violations via Rogue Wireless Access Points on PAWs
Privileged Access Workstations are dedicated to the administration of Tier 0 directory and identity systems:
* **Direct Enclave Penetration**: Enabling `icssvc` on a PAW allows the creation of an ad-hoc Wi-Fi software access point. An adversary or unauthorized wireless device within radio range can associate with the hotspot, establishing an unmonitored wireless bridge directly into the Tier 0 administrative network and bypassing 802.1X access controls, physical security boundaries, and network segregation (MITRE ATT&CK T1200 - Hardware Additions).
* **Adversary Traffic Sniffing and Lateral Movement**: Running an unauthorized Wi-Fi access point on a PAW exposes administrative network packets to wireless interception, man-in-the-middle attacks, and wireless de-authentication or handshake capture exploits.

### 2. PAW Clean Source and Radio Attack Surface Elimination
Under the clean source principle and Microsoft PAW guidelines:
* **Physical and Logical Boundary Integrity**: PAWs must be connected via dedicated, shielded wired Ethernet switch ports inside secure administrative enclaves. Over-the-air networking interfaces and software access points represent uncontrolled entry points into Tier 0 assets.
* **Prohibition of SoftAP Capabilities**: PAWs must never act as wireless routers, repeaters, or connection sharing hubs.
* **Driver Minimization**: Disabling `icssvc` shuts down the software access point stack and prevents Wi-Fi driver components from hosting wireless beacon frames, eliminating wireless exploit surface.

### 3. MITRE ATT&CK Mapping
* **T1200 - Hardware Additions**: Creating unauthorized wireless access points to bridge unauthenticated devices into Tier 0 networks.
* **T1049 - System Network Connections Discovery**: Exploiting multi-homed wireless interfaces to bypass network isolation boundaries.
* **T1557 - Adversary-in-the-Middle**: Intercepting or relaying administrative communications across ad-hoc wireless connections.

---

## Legacy Impact & Compatibility
* **Tier 0 Administrative Management**: Disabling `icssvc` has zero impact on Active Directory administration, server management tools (RSAT), PowerShell remoting, or Hyper-V administration.
* **Wireless Hotspot Disabled**: Mobile hotspot functionality is completely disabled. PAW administrators must not use administrative hardware for consumer device tethering.
* **Wired Network Best Practice**: Aligns with enterprise PAW design requirements mandating dedicated, isolated wired network access for Tier 0 management tasks.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the PAW GPO (e.g., `GPO_Hardening_PAW`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\System Services`
4. Locate `Windows Mobile Hotspot Service` (`icssvc`), double-click to define the policy, and select **Disabled**.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

[Download Script: Configure-DisablePawicssvc.ps1](../implementation_scripts/Configure-DisablePawicssvc.ps1)

```powershell
# Configure-DisablePawicssvc.ps1
# Description: Disables the unnecessary Windows Mobile Hotspot Service (icssvc) service on the local PAW.

Write-Host "Applying hardening requirement: Disable Windows Mobile Hotspot Service service on PAW..." -ForegroundColor Cyan

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

*To verify the startup type of this unnecessary service on the PAW:*

[Download Script: Get-PawicssvcStatus.ps1](../audit_scripts/Get-PawicssvcStatus.ps1)

```powershell
# Get-PawicssvcStatus.ps1
# Description: Audits the startup configuration of Windows Mobile Hotspot Service (icssvc) service on the local PAW system.

Write-Host "--- Auditing Windows Mobile Hotspot Service (icssvc) Service on PAW ---" -ForegroundColor Cyan

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
* **ANSSI Active Directory Hardening Guide**: Recommendations on limiting active background services on sensitive hosts
* **DoD Windows 11 Computer STIG v2r6**: Unnecessary services restrictions
