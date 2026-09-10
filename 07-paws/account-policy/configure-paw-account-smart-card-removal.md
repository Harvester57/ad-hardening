# [REQ-PAW-155] Account Policy: Smart Card Removal Behavior for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) dedicated to Tier 0 directory administration.
* **Operating Systems**: Windows 10 Enterprise (1809 and above), Windows 11 Enterprise (all builds).

---

## Implementation Details
* **Priority**: High
* **Policy Category**: Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
* **Policy Setting**: Interactive logon: Smart card removal behavior: `Lock Workstation` (value `1`)
* **Supported On**: Windows 10 Enterprise / Windows 11 Enterprise
* **Registry Key & Value**:
  * `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ScRemoveOption` = `"1"` (REG_SZ, 1 = Lock Workstation)
* **Associated Service**: Smart Card Removal Policy service (`SCPolicySvc`, Startup Type: `Automatic`)
* **Vulnerability References**:
  * MITRE ATT&CK: [T1200: Direct Physical Access](https://attack.mitre.org/techniques/T1200/), [T1078: Valid Accounts](https://attack.mitre.org/techniques/T1078/)

---

## Rationale

Privileged Access Workstations serve as high-value execution environments where an active administrative session possesses unconstrained directory authority. Unattended, unlocked consoles present an immediate target for physical tampering, unauthorized keystroke injection (e.g., Rubber Ducky payloads), and unauthorized administrative actions:

### Technical Threat Vectors and Defense Mechanics
1. **Binding Physical Presence to Active Session State (`ScRemoveOption = "1"`)**:
   Tier 0 PAWs enforce multi-factor authentication using physical hardware tokens (PIV, CAC, smart cards, or YubiKey cryptographic modules). When an administrator inserts their smart card and enters their PIN, the operating system verifies the hardware token. However, if the administrator steps away from the console without manually locking the screen (`Win + L`), the active desktop remains vulnerable. Configuring `ScRemoveOption = "1"` ("Lock Workstation") instructs Winlogon and the Smart Card Removal Policy service (`SCPolicySvc`) to detect token extraction and invoke `LockWorkstation()` immediately.
2. **Preventing Physical Console Hijacking**:
   In high-security administrative operations, walk-by physical compromise or insider intervention can occur within seconds of an administrator stepping away. Tying the desktop lock state to physical card removal creates a natural physical habit: administrators withdraw their token when moving away from their desk, ensuring zero opportunity for unauthorized physical interaction.
3. **Preserving Operational State vs Disruptive Logoff**:
   Windows supports several removal options:
   * `"0"` = No Action (Insecure: active session left completely unprotected upon card removal).
   * `"1"` = Lock Workstation (Optimal: session locks instantly, preserving active administrative consoles, background scripts, and open RSAT tools until the administrator re-authenticates).
   * `"2"` = Force Logoff (Aggressive: terminates all active processes immediately; causes data loss during complex directory migrations or long-running administrative PowerShell tasks).
   Setting `ScRemoveOption = "1"` provides maximum physical security while preserving operational continuity.
4. **Prerequisite Service Dependency**:
   The smart card removal policy requires the Smart Card Removal Policy service (`SCPolicySvc`) to be set to Automatic and running. This service registers with the PC/SC subsystem to monitor `SCARD_STATE_EMPTY` transitions.

---

## Legacy Impact & Compatibility

* **Administrator Habit Formation**: Administrators must carry their smart card with them whenever they leave the PAW console. Unlocking the session requires re-inserting the token into the reader and entering the PIN.
* **Smart Card Reader Hardware**: Workstations must be equipped with compliant CCID USB smart card readers or integrated keyboard readers that accurately report card removal events.
* **Service Dependency**: If `SCPolicySvc` is stopped or disabled, removal events will not trigger a session lock. Hardening baselines should verify that `SCPolicySvc` is configured for Automatic startup.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the PAW GPO linked to the PAW Organizational Unit (e.g., `GPO_Hardening_PAWs`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options`
4. Double-click **Interactive logon: Smart card removal behavior**.
5. Check **Define this policy setting** and select **Lock Workstation** (value `1`).
6. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\System Services`
7. Locate **Smart Card Removal Policy** service (`SCPolicySvc`), configure service startup mode to **Automatic**, and start the service.
8. Link the GPO to the dedicated PAW OU and force replication.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

[Download Script: Configure-PawAccountSmartCardRemoval.ps1](../implementation_scripts/Configure-PawAccountSmartCardRemoval.ps1)

```powershell
# Configure-PawAccountSmartCardRemoval.ps1
# Description: Configures Smart Card removal behavior to Lock Workstation and enables SCPolicySvc on PAWs.

Write-Host "Configuring PAW Smart Card removal behavior..." -ForegroundColor Cyan

# 1. Configure Winlogon ScRemoveOption
$WinlogonPath = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
if (-not (Test-Path $WinlogonPath)) {
    New-Item -Path $WinlogonPath -Force | Out-Null
}
Set-ItemProperty -Path $WinlogonPath -Name "ScRemoveOption" -Value "1" -Type String -Force

# 2. Ensure Smart Card Removal Policy service is configured for Automatic start
$ServiceName = "SCPolicySvc"
$Service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($null -ne $Service) {
    Set-Service -Name $ServiceName -StartupType Automatic
    if ($Service.Status -ne "Running") {
        Start-Service -Name $ServiceName -ErrorAction SilentlyContinue
    }
}

Write-Host "Smart card removal behavior set to Lock Workstation ('1') and service configured." -ForegroundColor Green
```

*To audit the hardening status:*

[Download Script: Get-PawAccountSmartCardRemovalStatus.ps1](../audit_scripts/Get-PawAccountSmartCardRemovalStatus.ps1)

```powershell
# Get-PawAccountSmartCardRemovalStatus.ps1
# Description: Audits Smart Card removal behavior and service status on PAWs.

Write-Host "--- Auditing PAW Smart Card Removal Behavior ---" -ForegroundColor Cyan

$WinlogonPath = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"

if (-not (Test-Path -Path $WinlogonPath)) {
    Write-Host "    [!] MISSING KEY: $WinlogonPath" -ForegroundColor Red
    Write-Output "Non-Compliant"
    exit 1
}

$Val = (Get-ItemProperty -Path $WinlogonPath -Name "ScRemoveOption" -ErrorAction SilentlyContinue).ScRemoveOption

if ($Val -eq "1") {
    Write-Host "    [+] ScRemoveOption is set to '$Val' (Lock Workstation - Secure)." -ForegroundColor Green
    Write-Output "Compliant"
    exit 0
} else {
    Write-Host "    [!] VULNERABLE: ScRemoveOption is set to '$Val' (Expected: '1')" -ForegroundColor Red
    Write-Output "Non-Compliant"
    exit 1
}
```

---

### Option C: Manual Verification

Verify the applied smart card removal registry setting using command prompt:
```cmd
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v ScRemoveOption
```
Confirm that `ScRemoveOption` is of type `REG_SZ` with value `"1"`.

Verify the Smart Card Removal Policy service status:
```cmd
sc query SCPolicySvc
```
Confirm that `STATE` indicates `RUNNING` and `START_TYPE` is `AUTO_START`.

---

## Sources & Compliance References
* **CIS Microsoft Windows 10 Enterprise Benchmark**: Section 2.3.9.5 (Ensure 'Interactive logon: Smart card removal behavior' is set to 'Lock Workstation')
* **CIS Microsoft Windows 11 Enterprise Benchmark**: Section 2.3.9.5 (Ensure 'Interactive logon: Smart card removal behavior' is set to 'Lock Workstation')
* **DoD Windows 11 Computer STIG**: Rule SV-220722r879622_rule (Smart card removal behavior)
* **ANSSI Active Directory Hardening Guide**: Section 3.4 (Physical Access Control and Hardware Token Removal Protections on PAWs)
* **Microsoft Security Baseline Focus**: Windows Client Security Baseline - Local Policies Security Options
* **Related Controls**: [REQ-END-166: Account Policy: Smart Card Removal Behavior for Endpoints](../../08-endpoints/account-policy/configure-end-account-smart-card-removal.md), [REQ-PAW-160: Account Policy: Windows Hello for Business and PIN Complexity for PAWs](configure-paw-account-hello-pin.md)
