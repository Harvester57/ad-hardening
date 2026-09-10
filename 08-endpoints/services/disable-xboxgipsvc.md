# [REQ-END-053] Disable Xbox Accessory Management Service (XboxGipSvc)

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers. *(For Tier 0 Privileged Access Workstations, refer to tightened baseline [REQ-PAW-053](../../07-paws/services/disable-xboxgipsvc.md)).*
* **Operating Systems**: Windows 10 (all supported editions), Windows 11 Enterprise/Pro, Windows Server 2016, 2019, 2022, and 2025.

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
The Xbox Accessory Management Service (`XboxGipSvc`, hosted in `svchost.exe` via `XboxGipSvc.dll`) manages connected Xbox peripherals, gamepads, steering wheels, headsets, and consumer wireless dongles by interfacing with the Xbox Game Input Protocol (GIP) kernel driver stack (`xboxgip.sys`).

### 1. Consumer Peripheral Driver Attack Surface in Enterprise Environments
Enterprise workstations and domain member servers have zero operational requirement to support consumer gaming peripherals:
* **Privileged Peripheral Management**: `XboxGipSvc` executes with high local system privileges (`LocalSystem` or `LocalService`) to manage accessory enumeration, firmware updating, and configuration over USB and 2.4 GHz proprietary wireless protocols.
* **Kernel Driver Interaction and IOCTL Interfaces**: The service interfaces directly with kernel-mode drivers (`xboxgip.sys`) through I/O Control (IOCTL) codes. Exposing complex kernel-mode driver stacks to unauthenticated physical USB connections introduces significant attack surface for local privilege escalation (LPE) and system crashes.

### 2. Malicious USB Hardware and Descriptor Fuzzing (BadUSB)
* Malicious actors with physical access or untrusted peripheral vendors can craft specialized USB microcontrollers (e.g., Teensy, Raspberry Pi Pico) presenting forged USB Human Interface Device (HID) descriptors and Xbox GIP device identifiers.
* If `XboxGipSvc` is running, Windows automatically engages the Xbox GIP parsing routines and service callbacks upon hardware insertion. Buffer overflow or memory safety defects in peripheral firmware parsers can lead directly to arbitrary kernel execution or privileged service takeover.

### 3. Least Functionality and Enterprise Baseline Compliance
* Operating gaming accessory management services directly contradicts CIS Benchmarks and DoD STIG requirements for enterprise workstation minimization.
* Disabling `XboxGipSvc` ensures that consumer gaming hardware does not trigger specialized privileged management daemons, reducing background memory overhead and eliminating unnecessary local RPC endpoints.

### 4. MITRE ATT&CK Mapping
* **T1200 - Hardware Additions**: Attackers introducing rogue physical USB devices mimicking gaming accessories to trigger vulnerable driver code paths.
* **T1068 - Exploitation for Privilege Escalation**: Exploiting flaws in peripheral management services or kernel driver IOCTL handlers to elevate privileges on local workstations.

---

## Legacy Impact & Compatibility
* **Enterprise Operations**: Disabling `XboxGipSvc` has zero impact on Active Directory operations, enterprise applications, productivity software, or standard USB peripherals (enterprise keyboards, mice, webcams, headsets, biometric scanners, and smart card readers).
* **Consumer Gaming Peripherals**: Xbox game controllers, racing wheels, and flight sticks connected via USB or wireless adapters will not receive firmware updates or proprietary accessory configuration software on hardened corporate endpoints. Standard DirectInput or generic HID functionality may still operate depending on underlying driver state.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the target endpoints GPO (e.g., `GPO_Hardening_Endpoints`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\System Services`
4. Locate `Xbox Accessory Management Service` (`XboxGipSvc`), double-click to define the policy, and select **Disabled**.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

[Download Script: Configure-DisableXboxGipSvc.ps1](../implementation_scripts/Configure-DisableXboxGipSvc.ps1)

```powershell
# Configure-DisableXboxGipSvc.ps1
# Description: Disables the unnecessary Xbox Accessory Management Service (XboxGipSvc) service.

Write-Host "Applying hardening requirement: Disable Xbox Accessory Management Service service..." -ForegroundColor Cyan

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

*To verify the startup type of this unnecessary service:*

[Download Script: Get-XboxGipSvcStatus.ps1](../audit_scripts/Get-XboxGipSvcStatus.ps1)

```powershell
# Get-XboxGipSvcStatus.ps1
# Description: Audits the startup configuration of Xbox Accessory Management Service (XboxGipSvc) service.

Write-Host "--- Auditing Xbox Accessory Management Service (XboxGipSvc) Service ---" -ForegroundColor Cyan

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
* **ANSSI Active Directory Hardening Guide**: Recommendations on host service minimization
* **DoD Windows 11 Computer STIG v2r6**: Unnecessary services restrictions
