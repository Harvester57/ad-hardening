# [REQ-PAW-165] Account Policy: Interactive Logon Security Options for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) dedicated to Tier 0 directory administration.
* **Operating Systems**: Windows 10 Enterprise (1809 and above), Windows 11 Enterprise (all builds).

---

## Implementation Details
* **Priority**: High
* **Policy Category**: Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
* **Policy Settings**:
  * Interactive logon: Do not require CTRL+ALT+DEL: `Disabled`
  * Interactive logon: Don't display last signed-in: `Enabled`
  * Audit: Shut down system immediately if unable to log security audits: `Disabled`
* **Supported On**: Windows 10 Enterprise / Windows 11 Enterprise
* **Registry Keys & Values**:
  * `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\DisableCAD` = `0` (REG_DWORD, Requires CTRL+ALT+DEL Secure Attention Sequence)
  * `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\DontDisplayLastUserName` = `1` (REG_DWORD, Hides last signed-in username on lock screen)
  * `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CrashOnAuditFail` = `0` (REG_DWORD, Disables blue-screen shutdown upon security audit log full)
* **Vulnerability References**:
  * MITRE ATT&CK: [T1056.002: Input Capture: GUI Input Capture](https://attack.mitre.org/techniques/T1056/002/), [T1087.001: Local Account Discovery](https://attack.mitre.org/techniques/T1087/001/), [T1499: Endpoint Denial of Service](https://attack.mitre.org/techniques/T1499/)

---

## Rationale

Interactive logon controls establish the initial verification boundary between the physical user, hardware input devices, and the Windows kernel. On Tier 0 Privileged Access Workstations, interactive logon settings must eliminate credential harvesting prompts, shoulder surfing, and denial-of-service vectors:

### Technical Threat Vectors and Defense Mechanics
1. **Secure Attention Sequence (SAS) Enforcement (`DisableCAD = 0`)**:
   The `CTRL+ALT+DEL` keystroke combination constitutes the Windows hardware Secure Attention Sequence (SAS). In the Windows kernel architecture, SAS interrupts are captured exclusively by the kernel keyboard class driver (`kbdclass.sys`) and routed directly to the trusted Winlogon process (`winlogon.exe`) running on the isolated Secure Desktop. Standard user-mode applications, unprivileged Trojan processes, and malicious keyloggers cannot intercept, simulate, or spoof this sequence. If CAD is not enforced (`DisableCAD = 1`), an attacker with local userland execution could display a pixel-perfect fake lock screen to capture administrative credentials. Requiring `CTRL+ALT+DEL` guarantees that administrators are interacting with the authentic operating system logon interface.
2. **Visual Reconnaissance and Account Enumeration Defense (`DontDisplayLastUserName = 1`)**:
   By default, Windows renders the username, display name, and domain of the last authenticated user on the logon and lock screens. In administrative facilities or shared operational centers, anyone walking past a locked PAW can record valid Tier 0 administrative account names. Furthermore, this knowledge eliminates 50% of the authentication credential set needed for password spraying or targeted credential attacks. Enforcing `DontDisplayLastUserName = 1` clears all identity artifacts from the lock screen, requiring administrators to manually supply both their username and PIN/smart card credential.
3. **Preventing Audit-Induced System Crashes (`CrashOnAuditFail = 0`)**:
   Historically, high-assurance security policies enforced `CrashOnAuditFail = 1`, which commands the Windows kernel to issue a blue-screen crash (`STOP 0x000000C0` / `STATUS_LOG_FILE_FULL`) if the Security event log becomes saturated and cannot write an audit event. In modern adversary tradecraft, an attacker aware of this setting could intentionally flood the event log with frivolous audit events to trigger an immediate, unrecoverable denial-of-service crash across critical administrative consoles. Setting `CrashOnAuditFail = 0` maintains workstation availability while paired with centralized Windows Event Forwarding (WEF) and expanded local log capacities.
4. **Tier 0 Operational Posture**:
   PAWs represent the supreme administrative plane. Requiring hardware SAS and concealing user account identities ensures physical and local isolation of high-privilege credentials.

---

## Legacy Impact & Compatibility

* **User Workflow**: Administrators must press `CTRL+ALT+DEL` to display the authentication prompt and must manually type their administrative username rather than selecting an account icon from a list.
* **Smart Card Workflows**: When using smart card or YubiKey authentication, inserting the token automatically presents the PIN prompt once `CTRL+ALT+DEL` is pressed.
* **Audit Overflow**: System operations will not halt if the Security event log reaches maximum capacity; instead, events will wrap according to configured event log retention policies.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the PAW GPO linked to the PAW Organizational Unit (e.g., `GPO_Hardening_PAWs`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options`
4. Configure the following policies:
   * **Interactive logon: Do not require CTRL+ALT+DEL**: Set to `Disabled` (value `0`)
   * **Interactive logon: Don't display last signed-in**: Set to `Enabled` (value `1`)
   * **Audit: Shut down system immediately if unable to log security audits**: Set to `Disabled` (value `0`)
5. Link the GPO to the dedicated PAW OU and force update via `gpupdate /force`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

[Download Script: Configure-PawAccountInteractiveLogon.ps1](../implementation_scripts/Configure-PawAccountInteractiveLogon.ps1)

```powershell
# Configure-PawAccountInteractiveLogon.ps1
# Description: Configures interactive logon security options (SAS requirement, hide last user, audit stability) on PAWs.

Write-Host "Configuring PAW interactive logon security options..." -ForegroundColor Cyan

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

[Download Script: Get-PawAccountInteractiveLogonStatus.ps1](../audit_scripts/Get-PawAccountInteractiveLogonStatus.ps1)

```powershell
# Get-PawAccountInteractiveLogonStatus.ps1
# Description: Audits interactive logon security options on PAWs.

Write-Host "--- Auditing PAW Interactive Logon Security Options ---" -ForegroundColor Cyan
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
* **DoD Windows 11 Computer STIG**: Rule SV-220713r879613_rule (Enforcing CTRL+ALT+DEL), Rule SV-220714r879614_rule (Hiding last username on lock screen)
* **ANSSI Active Directory Hardening Guide**: Section 3.4 (Interactive Logon Hardening and Shoulder-Surfing Mitigations)
* **Microsoft Security Baseline Focus**: Windows Client Security Baseline - Local Policies Security Options
* **Related Controls**: [REQ-END-176: Account Policy: Interactive Logon Security Options for Endpoints](../../08-endpoints/account-policy/configure-end-account-interactive-logon.md), [REQ-PAW-155: Account Policy: Smart Card Removal Behavior for PAWs](configure-paw-account-smart-card-removal.md)
