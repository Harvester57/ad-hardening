# [REQ-END-137] User Profile: Interactive Logon Inactivity Timeout

## Target Scope
* **Applicable Systems**: Tier 2 Client Workstations and Member Servers. *(For Tier 0 Privileged Access Workstations, refer to tightened baseline [REQ-PAW-126](../../07-paws/user-profile/configure-up-inactivity-timeout.md)).*
* **Operating Systems**: Windows 10 Enterprise/Professional (all supported builds), Windows 11 Enterprise/Pro, Windows Server 2016, 2019, 2022, and 2025.

---

## Implementation Details
* **Priority**: High
* **GPO Paths / Registry Locations**:
  * **Machine Inactivity Limit**:
    * GPO Path: `Computer Configuration\Windows Settings\Security Settings\Local Policies\Security Options\Interactive logon: Machine inactivity limit` -> Set to **900** seconds (or 15 minutes or less)
    * Registry Path: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`
    * Value Name: `InactivityTimeoutSecs`
    * Value Type: `REG_DWORD`
    * Value Data: `900` (15 minutes / Enforce automatic session screen lock)

---

## Rationale
In enterprise environments, authorized employees and operators frequently leave workstations unattended—to attend meetings, take breaks, or collaborate elsewhere in the facility. If a workstation remains unlocked while unattended, any individual with physical access to the machine can interact with the active user's session, execute unauthorized commands, exfiltrate sensitive files, or install persistence mechanisms without needing to authenticate.

### 1. Inactivity Tracking Architecture & Winlogon Mechanics
The Windows subsystem tracks user interaction across keyboard, mouse, and touch input devices:
* The Win32 subsystem monitors global input timestamps using the `GetLastInputInfo()` API.
* When the elapsed idle duration exceeds the threshold defined by `InactivityTimeoutSecs` (900 seconds / 15 minutes), the Windows Logon subsystem (`winlogon.exe`) calls `LockWorkStation()`.
* The desktop window station is immediately switched to the protected logon desktop (`winsta0\Winlogon`), revoking user-mode input access and displaying the lock screen authentication prompt.
* To resume work, the user must re-enter their password, PIN, smart card PIN, or biometric verification, re-validating their identity.

### 2. Threat Vectors & Walk-Up Attacks
* **Opportunistic Walk-Up Compromise**: An adversary, malicious visitor, or rogue insider in an office can walk up to an unlocked workstation and insert a malicious HID injection tool (e.g., USB Rubber Ducky), immediately executing pre-scripted payloads in the authenticated user's security context.
* **Data Exfiltration from Open Sessions**: Attackers can browse open enterprise email accounts, corporate portals, and internal document repositories that would otherwise require MFA to access.
* **Identity Impersonation**: Actions taken on an unlocked console appear in security logs as legitimate actions performed by the victim user, complicating forensic attribution and incident response.
* Enforcing `InactivityTimeoutSecs = 900` guarantees that sessions are systematically locked within 15 minutes of idle time.

### 3. MITRE ATT&CK Mapping
* **T1204 - User Execution**: Physical interaction with an unlocked, unattended desktop session.
* **T1078 - Valid Accounts**: Misusing an authenticated session without possessing the user's credentials.
* **T1056 - Input Capture**: Physical harvesting of open documents and data from unlocked screens.

---

## Legacy Impact & Compatibility
* **User Productivity**: 15 minutes (900 seconds) provides an optimal balance between robust physical security and user convenience, preventing premature session locks during brief reading or thinking periods.
* **Conference Rooms and Presentations**: Presentation devices, kiosks, or conference room screens may utilize specialized presentation mode exemptions via power settings, but standard employee workstations must strictly comply.
* **Zero Software Impact**: Background processes, long-running batch jobs, and system updates continue executing unimpeded while the workstation is in a locked state.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to workstations and member servers (e.g., `GPO_Hardening_Endpoints`).
3. Navigate to: `Computer Configuration \ Windows Settings \ Security Settings \ Local Policies \ Security Options`
4. Double-click **Interactive logon: Machine inactivity limit** and configure:
   * Check **Define this policy setting**
   * Set **The machine will be locked after**: `900` seconds
5. Link the GPO to the appropriate Organizational Unit and verify policy enforcement using `gpupdate /force`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to enforce the machine inactivity timeout limit:

[Download Script: Configure-Upinactivitytimeout.ps1](../implementation_scripts/Configure-Upinactivitytimeout.ps1)

```powershell
# Configure-Upinactivitytimeout.ps1
Write-Host "Applying User Profile restriction: inactivity-timeout..." -ForegroundColor Cyan

function Set-RegValue {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [string]$hive,
        [string]$keyPath,
        [string]$name,
        [string]$value,
        [string]$type
    )
    if ($PSCmdlet.ShouldProcess("$hive\$keyPath", "Set registry value $name to $value")) {
        $fullPath = "$hive\$keyPath"
        $parent = Split-Path -Path $fullPath
        if (-not (Test-Path $parent)) { New-Item -Path $parent -Force | Out-Null }
        if (-not (Test-Path $fullPath)) { New-Item -Path $fullPath -Force | Out-Null }
        Set-ItemProperty -Path $fullPath -Name $name -Value $value -Type $type -Force
    }
}
Set-RegValue "HKLM:" "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "InactivityTimeoutSecs" "900" "DWord"

```

*To audit the hardening status:*

[Download Script: Get-UpinactivitytimeoutStatus.ps1](../audit_scripts/Get-UpinactivitytimeoutStatus.ps1)

```powershell
# Get-UpinactivitytimeoutStatus.ps1
$script:Vulnerable = $false

function Test-RegValue {
    param (
        [string]$hive,
        [string]$keyPath,
        [string]$name,
        [string]$expected
    )
    $fullPath = "$hive\$keyPath"
    $val = Get-ItemProperty -Path $fullPath -Name $name -ErrorAction SilentlyContinue
    $actual = if ($val) { $val.$name } else { "" }
    if ($actual -ne $expected) {
        $script:Vulnerable = $true
    }
}
Test-RegValue "HKLM:" "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "InactivityTimeoutSecs" "900"

if ($script:Vulnerable) {
    Write-Output "Non-Compliant"
    exit 1
} else {
    Write-Output "Compliant"
    exit 0
}
```

---

## Sources & Compliance References
* **CIS Benchmark**: CIS Microsoft Windows 10 Enterprise Benchmark: Section 2.3.7.3; CIS Microsoft Windows 11 Enterprise Benchmark: Section 2.3.7.3; CIS Windows Server Benchmark: Section 2.3.7.3
* **DISA STIG**: Windows 10 STIG Rule WN10-SO-000070, Windows 11 STIG Rule WN11-SO-000070, NIST SP 800-53 Control AC-11
* **ANSSI Active Directory Hardening Guide**: Recommendation R37 (Securing administrative workstations and session timeouts)
* **Microsoft Security Guidance**: Interactive Logon: Machine Inactivity Limit Policy Specifications
