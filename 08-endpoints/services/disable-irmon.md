# [REQ-END-038] Disable Infrared Monitor Service (irmon)

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers. *(For Tier 0 Privileged Access Workstations, refer to tightened baseline [REQ-PAW-038](../../07-paws/services/disable-irmon.md)).*
* **Operating Systems**: Windows 10 (all supported editions), Windows 11 Enterprise/Pro, Windows Server 2016, 2019, 2022, and 2025.

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\System Services\Infrared monitor service` -> **Disabled**
  * **Registry Path**: `HKLM\SYSTEM\CurrentControlSet\Services\irmon`
  * **Value Name**: `Start`
  * **Value Type**: `REG_DWORD`
  * **Value Data**: `4` (Disabled)

---

## Rationale
The Infrared Monitor Service (`irmon`, hosted within `svchost.exe` via `irmon.dll`) manages line-of-sight optical wireless communications using the legacy Infrared Data Association (IrDA) protocol stack and Object Exchange (OBEX) profiles.

### 1. Legacy Optical Wireless Communications and Covert Data Channels
IrDA was developed in the 1990s to facilitate short-range, peer-to-peer wireless file transfers and peripheral connectivity prior to the widespread adoption of Wi-Fi Direct and modern Bluetooth:
* **Unauthenticated Device Pairing**: When an infrared optical transceiver (built-in or USB dongle) is detected, `irmon` automatically activates and listens for optical beacons from other IrDA devices within line-of-sight. Pairing and file transfer protocols historically operated without robust cryptographic mutual authentication.
* **Bypassing Perimeter Network Controls**: An unauthorized party in physical proximity (e.g., in a conference room, public workspace, or through an exterior window using focused optical receivers) could exploit active infrared interfaces to initiate unauthorized OBEX data transfers or exfiltrate sensitive files, completely bypassing host-based firewalls, network proxy servers, and egress monitoring systems.

### 2. Rogue Hardware and Peripheral Attack Surface
While modern enterprise laptops and workstations no longer ship with integrated IrDA hardware, legacy driver stacks remain embedded in Windows:
* **Rogue USB Dongle Exploitation**: If a user or malicious actor connects an inexpensive USB-to-IrDA adapter, Windows automatically loads the associated USB and IrDA driver stacks and starts `irmon`. This opens an unmonitored wireless communication channel.
* **Driver and Protocol Stack Vulnerabilities**: Legacy protocol stacks like IrDA receive limited ongoing security auditing compared to modern network stacks. Unchecked buffers in OBEX parsers or IrDA frame processors can be leveraged for denial-of-service or privilege escalation attacks.

### 3. Least Functionality in Corporate Workstations
* Infrared communication is an obsolete technology that has been replaced by secure, authenticated, and centrally managed enterprise communication standards.
* Disabling `irmon` enforces the principle of least functionality (NIST SP 800-53 CM-7) and eliminates an unmanaged physical wireless vector across corporate endpoints.

### 4. MITRE ATT&CK Mapping
* **T1011 - Other Network Medium**: Adversaries using non-standard radio frequency (RF) or optical infrared communication channels to bypass corporate network segmentation and exfiltrate data.
* **T1200 - Hardware Additions**: Introducing unauthorized USB IrDA optical transceivers to establish rogue communications.
* **T1210 - Exploitation of Remote Services**: Targeting vulnerabilities in legacy wireless protocol daemons.

---

## Legacy Impact & Compatibility
* **Enterprise Operations**: Disabling `irmon` has zero impact on modern Active Directory domain services, enterprise wireless (Wi-Fi 6/6E/7), Bluetooth peripherals, smart cards, or cellular broadband connectivity.
* **Peripheral Compatibility**: Modern enterprise peripherals (keyboards, mice, headsets, mobile synchronization) do not utilize IrDA.
* **Legacy Specialized Hardware**: Extremely old industrial, medical, or diagnostic field equipment manufactured before 2005 that strictly depends on optical IrDA synchronization will not communicate with hardened endpoints. Such equipment must be retired or serviced via dedicated, air-gapped legacy bridge systems.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the target endpoints GPO (e.g., `GPO_Hardening_Endpoints`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\System Services`
4. Locate `Infrared monitor service` (`irmon`), double-click to define the policy, and select **Disabled**.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

[Download Script: Configure-Disableirmon.ps1](../implementation_scripts/Configure-Disableirmon.ps1)

```powershell
# Configure-Disableirmon.ps1
# Description: Disables the unnecessary Infrared monitor service (irmon) service.

Write-Host "Applying hardening requirement: Disable Infrared monitor service service..." -ForegroundColor Cyan

$ServiceName = "irmon"
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

[Download Script: Get-irmonStatus.ps1](../audit_scripts/Get-irmonStatus.ps1)

```powershell
# Get-irmonStatus.ps1
# Description: Audits the startup configuration of Infrared monitor service (irmon) service.

Write-Host "--- Auditing Infrared monitor service (irmon) Service ---" -ForegroundColor Cyan

$ServiceName = "irmon"
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
* **CIS Microsoft Windows Client Benchmark**: Section 5.8 (irmon)
* **ANSSI Active Directory Hardening Guide**: Recommendations on host service minimization
* **DoD Windows 11 Computer STIG v2r6**: Unnecessary services restrictions
