# [REQ-PAW-053] Disable Xbox Accessory Management Service for PAWs (XboxGipSvc)

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration. *(For Tier 2 client workstations and member servers, refer to baseline [REQ-END-053](../../08-endpoints/services/disable-xboxgipsvc.md)).*
* **Operating Systems**: Windows 10 Enterprise (1607+) and Windows 11 Enterprise.

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\System Services\Xbox Accessory Management Service` -> **Disabled**
  * **Registry Path**: `HKLM\SYSTEM\CurrentControlSet\Services\XboxGipSvc`
  * **Value Name**: `Start`
  * **Value Type**: `REG_DWORD`
  * **Value Data**: `4` (Disabled)

---

## Rationale
The Xbox Accessory Management Service (`XboxGipSvc`, hosted in `svchost.exe` via `XboxGipSvc.dll`) manages Xbox gamepads, wireless gaming dongles, and consumer gaming accessories by interfacing directly with the Xbox Game Input Protocol (GIP) driver stack (`xboxgip.sys`).

### 1. Enforcement of Clean Source Principle and Peripheral Device Whitelisting
Under Microsoft Privileged Access Workstation guidelines, Tier 0 systems must maintain strict physical, hardware, and driver isolation:
* **Strict Peripheral Device Control**: PAWs enforce strict Device Installation restrictions via Group Policy, permitting only administrative smart card readers, approved corporate keyboards, and mice. Gaming controllers, flight sticks, and proprietary wireless dongles are strictly prohibited on Tier 0 systems.
* **Elimination of Kernel Driver Exposure**: Operating `XboxGipSvc` loads background components that interact directly with the ring-0 kernel driver `xboxgip.sys`. Kernel-mode driver interfaces (IOCTLs) represent critical attack surface; vulnerabilities in consumer peripheral drivers could permit local privilege escalation, memory disclosure, or bypass of virtualization-based security (VBS).

### 2. Prevention of Hardware-Based Exploitation (BadUSB)
* High-value Tier 0 administration workstations are primary targets for physical hardware attacks and malicious USB accessories. An adversary with temporary physical access or a malicious insider could insert a programmable microcontroller masquerading as an Xbox gaming accessory.
* By ensuring `XboxGipSvc` is disabled, the system refuses to engage consumer accessory management routines or trigger background firmware query routines, neutralizing potential firmware parser exploits.

### 3. Absolute Least Functionality on Tier 0 Assets
* Directory administration consoles (Active Directory Users and Computers, Group Policy Management, PKI management, PowerShell remoting) have zero operational requirement for consumer gaming accessories.
* Eliminating non-administrative services ensures that only verified, mission-critical binaries execute on Tier 0 workstations, reducing the likelihood of privilege escalation against LSASS or credential theft.

### 4. MITRE ATT&CK Mapping
* **T1200 - Hardware Additions**: Adversaries attempting physical hardware compromise via malicious USB peripherals.
* **T1068 - Exploitation for Privilege Escalation**: Exploiting peripheral management services or kernel driver IOCTL handlers to achieve SYSTEM privileges on Tier 0 hosts.

---

## Legacy Impact & Compatibility
* **Administrative Operations**: Disabling `XboxGipSvc` is completely transparent to all Tier 0 management tasks, including RSAT, PowerShell Remoting, Active Directory Administrative Center, GPMC, and Hyper-V/ESXi administrative consoles.
* **Hardware Compatibility**: Standard enterprise PAW peripherals (smart cards, YubiKeys, FIPS 140-2 tokens, enterprise keyboards and mice) do not utilize the Xbox Game Input Protocol and operate without interruption.
* **Compatibility Exception**: There are zero legitimate enterprise or administrative dependencies on Xbox accessory services on Privileged Access Workstations.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the PAW GPO (e.g., `GPO_Hardening_PAW`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\System Services`
4. Locate `Xbox Accessory Management Service` (`XboxGipSvc`), double-click to define the policy, and select **Disabled**.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

[Download Script: Configure-DisablePawXboxGipSvc.ps1](../implementation_scripts/Configure-DisablePawXboxGipSvc.ps1)

```powershell
# Configure-DisablePawXboxGipSvc.ps1
# Description: Disables the unnecessary Xbox Accessory Management Service (XboxGipSvc) service on the local PAW.

Write-Host "Applying hardening requirement: Disable Xbox Accessory Management Service service on PAW..." -ForegroundColor Cyan

$ServiceName = "XboxGipSvc"
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

[Download Script: Get-PawXboxGipSvcStatus.ps1](../audit_scripts/Get-PawXboxGipSvcStatus.ps1)

```powershell
# Get-PawXboxGipSvcStatus.ps1
# Description: Audits the startup configuration of Xbox Accessory Management Service (XboxGipSvc) service on the local PAW system.

Write-Host "--- Auditing Xbox Accessory Management Service (XboxGipSvc) Service on PAW ---" -ForegroundColor Cyan

$ServiceName = "XboxGipSvc"
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
* **CIS Microsoft Windows Client Benchmark**: Section 5.44 (XboxGipSvc)
* **ANSSI Active Directory Hardening Guide**: Recommendations on limiting active background services on sensitive hosts
* **DoD Windows 11 Computer STIG v2r6**: Unnecessary services restrictions
