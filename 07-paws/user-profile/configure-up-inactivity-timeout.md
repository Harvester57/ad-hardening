# [REQ-PAW-126] User Profile: Interactive Logon Inactivity Timeout for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 Active Directory and identity infrastructure administration. *(For Tier 2 Client Workstations and Member Servers, refer to [REQ-END-137](../../08-endpoints/user-profile/configure-up-inactivity-timeout.md)).*
* **Operating Systems**: Windows 10 Enterprise (1607+) and Windows 11 Enterprise.

---

## Implementation Details
* **Priority**: High
* **GPO Paths / Registry Locations**:
  * **Machine Inactivity Limit**:
    * GPO Path: `Computer Configuration\Windows Settings\Security Settings\Local Policies\Security Options\Interactive logon: Machine inactivity limit` -> Set to **900** seconds (or 15 minutes or less; 600 seconds recommended for high-security Tier 0 operations)
    * Registry Path: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`
    * Value Name: `InactivityTimeoutSecs`
    * Value Type: `REG_DWORD`
    * Value Data: `900` (15 minutes / Enforce automatic session screen lock)

---

## Rationale
Privileged Access Workstations (PAWs) are dedicated physical or virtual workstations exclusively utilized by Tier 0 identity administrators to manage Active Directory Domain Services, PKI root certification authorities, and privileged directory infrastructure. During an active administrative session, a PAW routinely hosts high-privilege credentials:
* In-memory Kerberos Ticket Granting Tickets (TGTs) belonging to Domain Admins, Enterprise Admins, or Schema Admins.
* Physical hardware security tokens (FIDO2 keys, PIV/CAC smart cards, YubiKeys) plugged into USB ports with unlocked PIN caching.
* Open elevated PowerShell consoles, Active Directory Administrative Center sessions, and Microsoft Management Consoles (MMCs) possessing unconstrained administrative control over the directory.

If an administrator steps away from their PAW without manually locking the console (e.g., to attend a meeting, take a phone call, or converse with colleagues), an unlocked workstation presents an existential threat to the entire Active Directory forest.

### 1. Inactivity Tracking Architecture & Winlogon Mechanics
Windows tracks input events at the kernel and Win32 subsystem layers:
* The Win32 subsystem tracks keyboard, mouse, and biometric input timestamps via the `GetLastInputInfo()` API.
* When the elapsed idle duration exceeds the configured threshold in `InactivityTimeoutSecs` (900 seconds / 15 minutes), the Windows Logon subsystem (`winlogon.exe`) calls `LockWorkStation()`.
* The desktop window station is immediately transitioned from the active desktop (`winsta0\Default`) to the protected logon desktop (`winsta0\Winlogon`).
* All user-mode input access to running administrative applications, command prompts, and remote server management tools is terminated.
* To unlock the workstation, the administrator must present re-authentication factors (smart card PIN, Windows Hello for Business biometric, or privileged password), re-validating physical presence and authorization.

### 2. Walk-Up Physical Threats to Tier 0 Environments
* **Opportunistic Physical Session Hijacking**: Anyone with physical access to the room—cleaning personnel, maintenance contractors, visitors, or rogue colleagues—can walk up to an unlocked PAW and execute catastrophic administrative actions without knowing the administrator's password.
* **Hardware Keystroke Injection (HID Attacks)**: An adversary can insert a pre-programmed malicious USB device (e.g., Rubber Ducky, Bash Bunny) that emulates an ultra-fast keyboard. In an unlocked Tier 0 session, such a device can spawn an elevated PowerShell prompt, execute DCSync via Mimikatz, add a backdoored account to Domain Admins, or deploy ransomware across domain controllers within seconds.
* **Smart Card PIN Cache Exploitation**: When a smart card remains inserted in an unlocked console, Windows Cryptographic Service Providers (CSPs) cache the PIN in memory for the duration of the logon session. An attacker at an unlocked PAW can sign arbitrary Kerberos requests or forge certificates without re-entering the PIN.
* Enforcing `InactivityTimeoutSecs = 900` (or 600) guarantees that the window of exposure for unattended PAWs is strictly bounded.

### 3. MITRE ATT&CK Mapping
* **T1204 - User Execution**: Physical execution of unauthorized commands via an unattended administrative session.
* **T1078 - Valid Accounts**: Usurping an authenticated Tier 0 administrative session without possessing the user's password or smart card credentials.
* **T1056 - Input Capture**: Physical observation and exfiltration of sensitive directory objects displayed on unattended screens.

---

## Legacy Impact & Compatibility
* **Zero Operational Disruption**: PAWs are dedicated, hardened single-purpose workstations. They do not run unattended background presentation displays, digital signage, or public kiosks.
* **Background Tasks Continue**: Long-running Active Directory maintenance scripts, server backups, or directory queries continue executing unimpeded in the background while the workstation is in a locked state.
* **User Habituation**: While administrators must develop the discipline of manually pressing `Win + L` whenever leaving their desks, the automated 15-minute inactivity timeout provides an essential safety net that prevents human error from compromising Tier 0 assets.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to the PAW Organizational Unit (e.g., `GPO_Hardening_PAWs`).
3. Navigate to: `Computer Configuration \ Windows Settings \ Security Settings \ Local Policies \ Security Options`
4. Double-click **Interactive logon: Machine inactivity limit** and configure:
   * Check **Define this policy setting**
   * Set **The machine will be locked after**: `900` seconds (or `600` seconds for tightened Tier 0 environments)
5. Link the GPO to the dedicated PAW Organizational Unit and enforce policy application using `gpupdate /force`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to enforce the machine inactivity timeout limit on PAWs:

[Download Script: Configure-PawUpinactivitytimeout.ps1](../implementation_scripts/Configure-PawUpinactivitytimeout.ps1)

```powershell
# Configure-PawUpinactivitytimeout.ps1
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

[Download Script: Get-PawUpinactivitytimeoutStatus.ps1](../audit_scripts/Get-PawUpinactivitytimeoutStatus.ps1)

```powershell
# Get-PawUpinactivitytimeoutStatus.ps1
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
* **CIS Microsoft Windows 10 Enterprise Benchmark**: Section 2.3.7.3 (L1 - Ensure 'Interactive logon: Machine inactivity limit' is set to '900 or fewer second(s), but not 0')
* **CIS Microsoft Windows 11 Enterprise Benchmark**: Section 2.3.7.3 (L1 - Ensure 'Interactive logon: Machine inactivity limit' is set to '900 or fewer second(s), but not 0')
* **DISA STIG**: Windows 10 STIG Rule WN10-SO-000070, Windows 11 STIG Rule WN11-SO-000070, NIST SP 800-53 Control AC-11 (Device Lock)
* **ANSSI Active Directory Hardening Guide**: Recommendation R37 (Securing administrative workstations, physical security, and session timeouts)
* **Microsoft Privileged Access Workstation (PAW) Guidance**: Physical Security and Console Session Lockdown Principles
