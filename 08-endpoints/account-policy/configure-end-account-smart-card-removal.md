# [REQ-END-166] Account Policy: Smart Card Removal Behavior for Endpoints

## Target Scope
* **Applicable Systems**: Tier 2 Client Workstations and Member Servers.
* **Operating Systems**: Windows 10 Enterprise/Professional (1809 and above), Windows 11 Enterprise/Professional (all builds), Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: High
* **Policy Category**: Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
* **Policy Setting**: Interactive logon: Smart card removal behavior: `Lock Workstation` (value `1`)
* **Supported On**: Windows 10 / Windows 11 / Windows Server 2016 and above
* **Registry Key & Value**:
  * `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ScRemoveOption` = `"1"` (REG_SZ, 1 = Lock Workstation)
* **Associated Service**: Smart Card Removal Policy service (`SCPolicySvc`, Startup Type: `Automatic`)
* **Vulnerability References**:
  * MITRE ATT&CK: [T1200: Direct Physical Access](https://attack.mitre.org/techniques/T1200/), [T1078: Valid Accounts](https://attack.mitre.org/techniques/T1078/)

---

## Rationale

In enterprise environments deploying physical smart cards, PIV/CAC badges, or FIDO2 cryptographic tokens for endpoint authentication, removing the physical token must immediately transition the host to a secure state. Hardening smart card removal behavior protects against unauthorized physical console access:

### Technical Threat Vectors and Defense Mechanics
1. **Automated Session Lockdown (`ScRemoveOption = "1"`)**:
   Users frequently step away from their desks for meetings, breaks, or consultations without manually invoking `Win + L` to lock their screens. An unattended, unlocked workstation leaves enterprise email, intranet portals, file shares, and network credentials completely exposed to walk-by tampering or physical espionage. Configuring `ScRemoveOption = "1"` ("Lock Workstation") ensures that whenever the user extracts their physical badge or token from the reader, Winlogon automatically locks the desktop session immediately.
2. **Preserving Operational Continuity**:
   Windows offers three operational responses to token extraction:
   * `"0"` = No Action (Leaves the desktop session active and unlocked).
   * `"1"` = Lock Workstation (Instantly locks the console; open applications, documents, and network connections remain active in memory).
   * `"2"` = Force Logoff (Instantly terminates the user session and closes all running software, risking unsaved data loss).
   Configuring `"1"` strikes the optimal balance: it achieves total physical lock security while allowing employees to resume work immediately upon re-inserting the token and typing their PIN.
3. **Preventing Session Takeover and Rogue Keystroke Injection**:
   Leaving a workstation physically unlocked enables physical access attacks, such as inserting a malicious USB HID device (e.g., Rubber Ducky or Bash Bunny) that can execute automated PowerShell download cradles or reverse shells in a fraction of a second. Requiring card removal to lock the machine eliminates this physical opportunity.
4. **Service Prerequisite (`SCPolicySvc`)**:
   The removal detection logic requires the Windows Smart Card Removal Policy service (`SCPolicySvc`) to be running. This service registers with the Windows smart card resource manager to monitor card insertion and extraction events.

---

## Legacy Impact & Compatibility

* **End-User Habits**: Employees must be informed that removing their smart card badge will lock the workstation. To continue working, they must re-insert the card and enter their PIN.
* **Non-Smart Card Users**: On workstations where users authenticate using username/password or Windows Hello for Business without physical smart card readers, this policy has zero negative impact—it remains dormant until a smart card session is initiated.
* **Smart Card Removal Service Requirement**: The `SCPolicySvc` service must be configured for Automatic startup across the enterprise fleet.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the GPO linked to workstations and member servers (e.g., `GPO_Hardening_Endpoints`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options`
4. Double-click **Interactive logon: Smart card removal behavior**.
5. Check **Define this policy setting** and select **Lock Workstation** (value `1`).
6. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\System Services`
7. Locate the **Smart Card Removal Policy** service (`SCPolicySvc`), set startup to **Automatic**, and start the service.
8. Link the GPO to the appropriate workstation and server Organizational Units.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

[Download Script: Configure-EndAccountSmartCardRemoval.ps1](../implementation_scripts/Configure-EndAccountSmartCardRemoval.ps1)

```powershell
# Configure-EndAccountSmartCardRemoval.ps1
# Description: Configures Smart Card removal behavior to Lock Workstation and enables SCPolicySvc on Endpoints.

Write-Host "Configuring Endpoint Smart Card removal behavior..." -ForegroundColor Cyan

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

[Download Script: Get-EndAccountSmartCardRemovalStatus.ps1](../audit_scripts/Get-EndAccountSmartCardRemovalStatus.ps1)

```powershell
# Get-EndAccountSmartCardRemovalStatus.ps1
# Description: Audits Smart Card removal behavior and service status on Endpoints.

Write-Host "--- Auditing Endpoint Smart Card Removal Behavior ---" -ForegroundColor Cyan

$WinlogonPath = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"

if (-not (Test-Path $WinlogonPath)) {
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

Verify the applied registry setting via command prompt:
```cmd
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v ScRemoveOption
```
Confirm that `ScRemoveOption` is `REG_SZ` with value `"1"`.

Verify the Smart Card Removal Policy service state:
```cmd
sc query SCPolicySvc
```
Confirm that `STATE` is `RUNNING` and `START_TYPE` is `AUTO_START`.

---

## Sources & Compliance References
* **CIS Microsoft Windows 10 Enterprise Benchmark**: Section 2.3.9.5 (Ensure 'Interactive logon: Smart card removal behavior' is set to 'Lock Workstation')
* **CIS Microsoft Windows 11 Enterprise Benchmark**: Section 2.3.9.5 (Ensure 'Interactive logon: Smart card removal behavior' is set to 'Lock Workstation')
* **CIS Microsoft Windows Server 2022 Benchmark**: Section 2.3.9.5 (Ensure 'Interactive logon: Smart card removal behavior' is set to 'Lock Workstation')
* **DoD Windows 11 Computer STIG**: Rule SV-220722r879622_rule (Smart card removal behavior)
* **ANSSI Active Directory Hardening Guide**: Recommendations on hardware token lifecycle and physical console session protection
* **Microsoft Security Baseline Focus**: Windows Client Security Baseline - Local Policies Security Options
* **Related Controls**: [REQ-PAW-155: Account Policy: Smart Card Removal Behavior for PAWs](../../07-paws/account-policy/configure-paw-account-smart-card-removal.md), [REQ-END-171: Account Policy: Windows Hello for Business and PIN Complexity for Endpoints](configure-end-account-hello-pin.md)
