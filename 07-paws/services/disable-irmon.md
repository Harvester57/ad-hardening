# [REQ-PAW-038] Disable Infrared Monitor Service for PAWs (irmon)

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration. *(For Tier 2 client workstations and member servers, refer to baseline [REQ-END-038](../../08-endpoints/services/disable-irmon.md)).*
* **Operating Systems**: Windows 10 Enterprise (1607+) and Windows 11 Enterprise.

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
The Infrared Monitor Service (`irmon`, hosted within `svchost.exe` via `irmon.dll`) provides management and discovery functions for the legacy Infrared Data Association (IrDA) optical protocol stack and Object Exchange (OBEX) protocol.

### 1. Enforcement of Clean Source Isolation and RF/Optical Boundaries
Under Microsoft Privileged Access Workstation guidelines, Tier 0 hosts must maintain strict, verifiable physical and logical isolation:
* **Air-Gap and Boundary Integrity**: Privileged Access Workstations must connect only via dedicated, isolated, and inspected network links (typically wired 802.1X enterprise LANs). All unmanaged or ad-hoc wireless channels—including Wi-Fi, Bluetooth, cellular modems, and optical infrared—must be rigorously disabled.
* **Mitigation of Physical Proximity Vectors**: In a physical office or data center environment, optical transceivers allow ad-hoc, unauthenticated communication with external devices within visual line of sight. Leaving `irmon` enabled allows an adversary with physical line-of-sight to attempt OBEX file drops or probe legacy protocol stacks on high-value Tier 0 administration machines.

### 2. Strict Peripheral Control and Rogue Hardware Prevention
* PAW baselines enforce rigorous peripheral whitelisting (permitting only approved wired keyboards, mice, and FIPS 201 compliant smart card readers).
* If an unauthorized or compromised USB-to-IrDA optical dongle is inserted into a PAW (whether by insider action or physical tampering), an active `irmon` service would automatically initialize the transceiver and broadcast presence. Disabling `irmon` in the operating system configuration ensures that even if hardware restrictions fail, the optical communication service cannot execute.

### 3. Absolute Least Functionality on Tier 0 Assets
* Directory administration tasks (Active Directory Users and Computers, Group Policy Management Console, PowerShell remoting to Domain Controllers) have zero operational requirement for infrared communications.
* Eliminating obsolete protocol daemons reduces the overall attack surface and prevents memory corruption vulnerabilities in legacy ring-3 DLLs or underlying ring-0 kernel drivers from being used for local privilege escalation against LSASS.

### 4. MITRE ATT&CK Mapping
* **T1011 - Other Network Medium**: Adversaries establishing covert optical wireless channels into isolated Tier 0 administrative enclaves.
* **T1200 - Hardware Additions**: Introducing rogue USB IrDA optical transceivers to compromise workstation isolation.
* **T1068 - Exploitation for Privilege Escalation**: Exploiting legacy protocol parsers to escalate privileges on administrative systems.

---

## Legacy Impact & Compatibility
* **Administrative Operations**: Disabling `irmon` is completely transparent to all Tier 0 management roles, including RSAT, PowerShell Remoting, Active Directory Administrative Center, GPMC, and virtual machine management consoles.
* **Hardware Compatibility**: Standard enterprise PAW hardware configurations (desktop workstations and hardened enterprise laptops) do not utilize infrared optical transceivers.
* **Compatibility Exception**: There are zero legitimate enterprise or administrative dependencies on infrared communications on Privileged Access Workstations.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the PAW GPO (e.g., `GPO_Hardening_PAW`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\System Services`
4. Locate `Infrared monitor service` (`irmon`), double-click to define the policy, and select **Disabled**.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

[Download Script: Configure-DisablePawirmon.ps1](../implementation_scripts/Configure-DisablePawirmon.ps1)

```powershell
# Configure-DisablePawirmon.ps1
# Description: Disables the unnecessary Infrared monitor service (irmon) service on the local PAW.

Write-Host "Applying hardening requirement: Disable Infrared monitor service service on PAW..." -ForegroundColor Cyan

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

*To verify the startup type of this unnecessary service on the PAW:*

[Download Script: Get-PawirmonStatus.ps1](../audit_scripts/Get-PawirmonStatus.ps1)

```powershell
# Get-PawirmonStatus.ps1
# Description: Audits the startup configuration of Infrared monitor service (irmon) service on the local PAW system.

Write-Host "--- Auditing Infrared monitor service (irmon) Service on PAW ---" -ForegroundColor Cyan

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
* **ANSSI Active Directory Hardening Guide**: Recommendations on limiting active background services on sensitive hosts
* **DoD Windows 11 Computer STIG v2r6**: Unnecessary services restrictions
