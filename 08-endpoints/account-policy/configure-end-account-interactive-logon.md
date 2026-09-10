# [REQ-END-176] Account Policy: Interactive Logon Security Options for Endpoints

## Target Scope
* **Applicable Systems**: Tier 2 Client Workstations and Member Servers.
* **Operating Systems**: Windows 10 Enterprise/Professional (1809 and above), Windows 11 Enterprise/Professional (all builds), Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: High
* **Policy Category**: Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
* **Policy Settings**:
  * Interactive logon: Do not require CTRL+ALT+DEL: `Disabled`
  * Interactive logon: Don't display last signed-in: `Enabled`
  * Audit: Shut down system immediately if unable to log security audits: `Disabled`
* **Supported On**: Windows 10 / Windows 11 / Windows Server 2016 and above
* **Registry Keys & Values**:
  * `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\DisableCAD` = `0` (REG_DWORD, Requires CTRL+ALT+DEL Secure Attention Sequence)
  * `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\DontDisplayLastUserName` = `1` (REG_DWORD, Hides last signed-in username on lock screen)
  * `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CrashOnAuditFail` = `0` (REG_DWORD, Disables blue-screen shutdown upon security audit log full)
* **Vulnerability References**:
  * MITRE ATT&CK: [T1056.002: Input Capture: GUI Input Capture](https://attack.mitre.org/techniques/T1056/002/), [T1087.001: Local Account Discovery](https://attack.mitre.org/techniques/T1087/001/), [T1499: Endpoint Denial of Service](https://attack.mitre.org/techniques/T1499/)

---

## Rationale

Interactive logon configurations govern how users authenticate at the physical console or remote desktop interface. Hardening these parameters across client endpoints and member servers defends against credential phishing, shoulder surfing, and intentional system crash exploits:

### Technical Threat Vectors and Defense Mechanics
1. **Preventing Rogue Credential Harvesters (`DisableCAD = 0`)**:
   The `CTRL+ALT+DEL` keystroke sequence triggers the hardware Secure Attention Sequence (SAS). Handled directly by the Windows kernel driver `kbdclass.sys`, this keystroke can only be received by the trusted Winlogon process on the isolated Secure Desktop. Unprivileged malware, userland scripts, or malicious background applications cannot intercept or simulate this hardware interrupt. If CAD is disabled (`DisableCAD = 1`), an attacker or malicious script running on an unlocked or shared workstation could present a full-screen GUI spoofing the Windows logon window to capture user credentials. Requiring `CTRL+ALT+DEL` ensures that credentials are typed exclusively into the genuine Windows Winlogon process.
2. **Mitigating Visual Reconnaissance & Credential Guessing (`DontDisplayLastUserName = 1`)**:
   By default, Windows renders the user name, domain, and avatar of the previous user on the lock screen. In corporate office spaces, open floor plans, or public customer-facing environments, unauthorized observers can read valid employee account names. When executing targeted password spraying, having pre-identified valid usernames substantially increases attack efficiency. Enforcing `DontDisplayLastUserName = 1` clears all identity clues from the logon interface, requiring users to manually enter both username and password/PIN.
3. **Preventing Denial-of-Service via Audit Saturation (`CrashOnAuditFail = 0`)**:
   Configuring `CrashOnAuditFail = 1` forces a system crash (`STOP 0x000000C0`) if the Security event log reaches its maximum size and cannot write events. An unprivileged user or malicious script could rapidly generate thousands of failed access events to deliberately exhaust event log space and crash the host. Setting `CrashOnAuditFail = 0` guarantees business continuity while relying on central SIEM log forwarding to detect audit saturation attempts.
4. **Defense-in-Depth Posture**:
   Applying these interactive logon settings across Tier 2 client workstations and member servers ensures that the entire enterprise fleet benefits from kernel-level logon security, protecting domain user accounts from local interception.

---

## Legacy Impact & Compatibility

* **End-User Experience**: Users must press `CTRL+ALT+DEL` before logging on and must type their username manually. Organizations transitioning to this policy should communicate this change to avoid helpdesk inquiries.
* **Smart Card and WHfB Logons**: Inserting a smart card or activating a FIDO2 token automatically navigates to the PIN prompt once the initial `CTRL+ALT+DEL` sequence is initiated.
* **Kiosk and Shared Public Displays**: Specialized single-purpose kiosk systems that utilize automatic logon accounts may require dedicated organizational units with tailored interactive logon policies. Standard enterprise desktop computers and servers must strictly enforce this control.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the GPO linked to workstations and member servers (e.g., `GPO_Hardening_Endpoints`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options`
4. Configure the following policies:
   * **Interactive logon: Do not require CTRL+ALT+DEL**: Set to `Disabled` (value `0`)
   * **Interactive logon: Don't display last signed-in**: Set to `Enabled` (value `1`)
   * **Audit: Shut down system immediately if unable to log security audits**: Set to `Disabled` (value `0`)
5. Link the GPO to the appropriate workstation and server Organizational Units.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

[Download Script: Configure-EndAccountInteractiveLogon.ps1](../implementation_scripts/Configure-EndAccountInteractiveLogon.ps1)

```powershell
# Configure-EndAccountInteractiveLogon.ps1
# Description: Configures interactive logon security options (SAS requirement, hide last user, audit stability) on Endpoints.

Write-Host "Configuring Endpoint interactive logon security options..." -ForegroundColor Cyan

$SystemPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
if (-not (Test-Path -Path $SystemPath)) {
    New-Item -Path $SystemPath -Force | Out-Null
}

Set-ItemProperty -Path $SystemPath -Name "DisableCAD" -Value 0 -Type DWord -Force
Set-ItemProperty -Path $SystemPath -Name "DontDisplayLastUserName" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $SystemPath -Name "CrashOnAuditFail" -Value 0 -Type DWord -Force

Write-Host "Interactive logon security options applied successfully." -ForegroundColor Green
```

*To audit the hardening status:*

[Download Script: Get-EndAccountInteractiveLogonStatus.ps1](../audit_scripts/Get-EndAccountInteractiveLogonStatus.ps1)

```powershell
# Get-EndAccountInteractiveLogonStatus.ps1
# Description: Audits interactive logon security options on Endpoints.

Write-Host "--- Auditing Endpoint Interactive Logon Security Options ---" -ForegroundColor Cyan
$script:Vulnerable = $false

$SystemPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

function Test-RegVal ($Name, $Expected) {
    if (-not (Test-Path -Path $SystemPath)) {
        Write-Host "    [!] MISSING KEY: $SystemPath" -ForegroundColor Red
        $script:Vulnerable = $true
        return
    }
    $Prop = Get-ItemProperty -Path $SystemPath -Name $Name -ErrorAction SilentlyContinue
    if ($null -eq $Prop -or $null -eq $Prop.$Name) {
        Write-Host "    [!] MISSING VALUE: $Name under $SystemPath (Expected: $Expected)" -ForegroundColor Red
        $script:Vulnerable = $true
        return
    }
    $Val = $Prop.$Name
    if ($Val -ne $Expected) {
        Write-Host "    [!] VULNERABLE: $Name is '$Val' (Expected: $Expected)" -ForegroundColor Red
        $script:Vulnerable = $true
    } else {
        Write-Host "    [+] $($Name): $Val (Secure)" -ForegroundColor Green
    }
}

Test-RegVal "DisableCAD" 0
Test-RegVal "DontDisplayLastUserName" 1
Test-RegVal "CrashOnAuditFail" 0

if ($script:Vulnerable) {
    Write-Output "Non-Compliant"
    exit 1
} else {
    Write-Output "Compliant"
    exit 0
}
```

---

### Option C: Manual Verification

Verify the applied registry configuration using command line queries:
```cmd
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v DisableCAD
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v DontDisplayLastUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v CrashOnAuditFail
```
Confirm that `DisableCAD` is `0x0`, `DontDisplayLastUserName` is `0x1`, and `CrashOnAuditFail` is `0x0`.

---

## Sources & Compliance References
* **CIS Microsoft Windows 10 Enterprise Benchmark**: Section 2.3.2.2 (Ensure 'Audit: Shut down system immediately if unable to log security audits' is set to 'Disabled'), Section 2.3.7.1 (Ensure 'Interactive logon: Do not require CTRL+ALT+DEL' is set to 'Disabled'), Section 2.3.7.2 (Ensure 'Interactive logon: Don't display last signed-in' is set to 'Enabled')
* **CIS Microsoft Windows 11 Enterprise Benchmark**: Section 2.3.2.2, Section 2.3.7.1, Section 2.3.7.2
* **CIS Microsoft Windows Server 2022 Benchmark**: Section 2.3.2.2, Section 2.3.7.1, Section 2.3.7.2
* **DoD Windows 11 Computer STIG**: Rule SV-220713r879613_rule (Enforcing CTRL+ALT+DEL), Rule SV-220714r879614_rule (Hiding last username on lock screen)
* **ANSSI Active Directory Hardening Guide**: Recommendations on interactive logon hardening and physical console security
* **Microsoft Security Baseline Focus**: Windows Client Security Baseline - Local Policies Security Options
* **Related Controls**: [REQ-PAW-165: Account Policy: Interactive Logon Security Options for PAWs](../../07-paws/account-policy/configure-paw-account-interactive-logon.md), [REQ-END-166: Account Policy: Smart Card Removal Behavior for Endpoints](configure-end-account-smart-card-removal.md)
