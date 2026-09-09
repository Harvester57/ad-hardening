# [REQ-END-182] Administrative Templates: MSS System and Session Security Protections

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers.
* **Operating Systems**: Windows 10 (and above) Enterprise/Professional, Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: High
* **Policy Category**: Computer Configuration -> Policies -> Windows Settings -> Security Settings -> Local Policies -> Security Options (MSS Settings)
* **Policy Settings**:
  * MSS: (AutoAdminLogon) Enable Automatic Logon
  * MSS: (SafeDllSearchMode) Enable Safe DLL search mode
  * MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires
  * MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning
* **Registry Keys & Values**:
  * `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\AutoAdminLogon` = `"0"` (REG_SZ)
  * `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\ScreenSaverGracePeriod` = `5` (REG_DWORD)
  * `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\SafeDllSearchMode` = `1` (REG_DWORD)
  * `HKLM\SYSTEM\CurrentControlSet\Services\Eventlog\Security\WarningLevel` = `90` (REG_DWORD)
* **Vulnerability References**: MITRE ATT&CK: T1574.001 (DLL Search Order Hijacking), T1552.002 (Credentials in Registry), T1070.001 (Clear Windows Event Logs), T1200 (Hardware Additions / Physical Access)

---

## Rationale

The Microsoft Solutions for Security (MSS) baseline settings provide low-level kernel, session manager, and authentication subsystem protections. These settings address fundamental Windows operating system security behaviors, including DLL search-order resolution, automatic logon credential storage, physical console lockout latency, and security event log capacity alerting.

### Technical Threat Vectors & System Protections
1. **DLL Search-Order Hijacking Mitigation (`SafeDllSearchMode = 1`)**: When an executable calls `LoadLibrary()` or `LoadLibraryEx()` without specifying an absolute path, Windows searches for the requested DLL across predefined locations. In legacy or unhardened mode, the Current Working Directory (CWD) is evaluated immediately after the application directory (position 2), prior to `%SystemRoot%\System32`. If an attacker tricks a user into opening an application from an untrusted or world-writable directory (e.g., `C:\Temp`, downloads folders, or an SMB file share containing a malicious DLL named `version.dll` or `cryptbase.dll`), the executable loads the attacker's payload. Enabling Safe DLL Search Mode shifts the current directory to position 5, evaluating `%SystemRoot%\System32`, `%SystemRoot%\System`, and `%SystemRoot%` first, neutralizing CWD-based DLL preloading attacks.
2. **Preventing Plaintext Credential Storage & Unattended Access (`AutoAdminLogon = 0`)**: Windows AutoAdminLogon allows automated interactive logons upon system reboot. To accomplish this, Windows stores the username, domain, and unencrypted cleartext password (`DefaultPassword`) in the local registry. Any local user, remote administrator, or offline registry extraction tool can easily dump these plain-text credentials. Furthermore, automatic logon leaves unattended workstations booted directly into an authenticated session. Enforcing `AutoAdminLogon = 0` guarantees that an interactive credential challenge is mandatory at boot.
3. **Minimizing Physical Console Hijacking Latency (`ScreenSaverGracePeriod = 5`)**: When a workstation screensaver activates or display lock initiates, Windows provides an unauthenticated grace period during which moving the mouse or pressing a key restores the session without prompting for credentials. If left unconfigured or set to excessive values, an opportunistic physical adversary walking past an unattended desk can seize control of an active corporate session. Constraining the grace period to 5 seconds or fewer closes this physical exploitation window.
4. **Early Warning for Security Event Log Exhaustion (`WarningLevel = 90`)**: Security event log exhaustion occurs when rapid logging activity or malicious event flooding threatens to overwrite critical forensic telemetry. When the security log reaches 90% capacity, the Local Security Authority (LSA) generates Event ID 1104 ("The security log is now full" warning), alerting security analysts and centralized SIEM collectors to rotate logs or investigate potential denial-of-service attempts before evidence is lost.

---

## Legacy Impact & Compatibility

* **Operational Impact**: Systems requiring automatic logon (such as interactive kiosks or dedicated display monitors) must utilize specialized restricted Shell Launcher configurations rather than Winlogon automatic logon. Applications that rely on loading custom DLLs from the current directory must be updated to place libraries in the application directory or specify full qualified file paths.
* **User Experience**: Workstations require authentication immediately after the screensaver engages (5-second grace window).
* **Forensic Integrity**: SIEM and operations teams receive early capacity warnings when security logs reach 90% utilization.
* **Rollout Recommendations**: Safe for immediate enterprise-wide deployment across all member servers and workstations.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to workstations and member servers (e.g., `GPO_Hardening_Endpoints`).
3. Navigate to:
   ```text
   Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options
   ```
4. Configure the following MSS policies (imported via `Secedit` or Microsoft Security Compliance Toolkit):
   * **MSS: (AutoAdminLogon) Enable Automatic Logon**: Set to `Disabled`
   * **MSS: (SafeDllSearchMode) Enable Safe DLL search mode**: Set to `Enabled`
   * **MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires**: Set to `Enabled: 5 or fewer seconds`
   * **MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning**: Set to `Enabled: 90% or less`
5. Click **Apply**, then click **OK** for each policy.
6. Link the GPO to the appropriate Organizational Unit (OU) and verify replication across all domain controllers.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to configure the administrative template registry values:

[Download Script: Configure-EndAtMssSystemProtections.ps1](../implementation_scripts/Configure-EndAtMssSystemProtections.ps1)

```powershell
#Configure-EndAtMssSystemProtections.ps1
# Description: Configures Administrative Templates: MSS System and Session Security Protections.

Write-Host "Configuring Administrative Templates: MSS System and Session Security Protections..." -ForegroundColor Cyan

if (-not (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon")) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoAdminLogon" -Value "0" -Type String -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "ScreenSaverGracePeriod" -Value 5 -Type DWord -Force

if (-not (Test-Path -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager")) {
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "SafeDllSearchMode" -Value 1 -Type DWord -Force

if (-not (Test-Path -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\Security")) {
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\Security" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\Security" -Name "WarningLevel" -Value 90 -Type DWord -Force

Write-Host "[+] Administrative Templates: MSS System and Session Security Protections applied successfully." -ForegroundColor Green
```

*To verify the configuration:*

[Download Script: Get-EndAtMssSystemProtectionsStatus.ps1](../audit_scripts/Get-EndAtMssSystemProtectionsStatus.ps1)

```powershell
#Get-EndAtMssSystemProtectionsStatus.ps1
# Description: Audits Administrative Templates: MSS System and Session Security Protections.

Write-Host "--- Auditing Administrative Templates: MSS System and Session Security Protections ---" -ForegroundColor Cyan
$script:Vulnerable = $false

$TargetKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
$ValueName = "AutoAdminLogon"
$ExpectedValue = "0"
if (Test-Path -Path $TargetKey) {
    $Prop = Get-ItemProperty -Path $TargetKey -Name $ValueName -ErrorAction SilentlyContinue
    if ($null -ne $Prop) {
        $Actual = $Prop.$ValueName
        if ($Actual -eq $ExpectedValue) {
            Write-Host "  [+] $ValueName = $($Actual) (Secure)" -ForegroundColor Green
        } else {
            Write-Host "  [!] MISMATCH: $ValueName = $($Actual) (Expected: $($ExpectedValue))" -ForegroundColor Red
            $script:Vulnerable = $true
        }
    } else {
        Write-Host "  [!] MISSING VALUE: $ValueName (Expected: $($ExpectedValue))" -ForegroundColor Red
        $script:Vulnerable = $true
    }
} else {
    Write-Host "  [!] MISSING KEY: $TargetKey" -ForegroundColor Red
    $script:Vulnerable = $true
}

$TargetKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
$ValueName = "ScreenSaverGracePeriod"
$ExpectedValue = 5
if (Test-Path -Path $TargetKey) {
    $Prop = Get-ItemProperty -Path $TargetKey -Name $ValueName -ErrorAction SilentlyContinue
    if ($null -ne $Prop) {
        $Actual = $Prop.$ValueName
        if ($Actual -eq $ExpectedValue) {
            Write-Host "  [+] $ValueName = $($Actual) (Secure)" -ForegroundColor Green
        } else {
            Write-Host "  [!] MISMATCH: $ValueName = $($Actual) (Expected: $($ExpectedValue))" -ForegroundColor Red
            $script:Vulnerable = $true
        }
    } else {
        Write-Host "  [!] MISSING VALUE: $ValueName (Expected: $($ExpectedValue))" -ForegroundColor Red
        $script:Vulnerable = $true
    }
} else {
    Write-Host "  [!] MISSING KEY: $TargetKey" -ForegroundColor Red
    $script:Vulnerable = $true
}

$TargetKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"
$ValueName = "SafeDllSearchMode"
$ExpectedValue = 1
if (Test-Path -Path $TargetKey) {
    $Prop = Get-ItemProperty -Path $TargetKey -Name $ValueName -ErrorAction SilentlyContinue
    if ($null -ne $Prop) {
        $Actual = $Prop.$ValueName
        if ($Actual -eq $ExpectedValue) {
            Write-Host "  [+] $ValueName = $($Actual) (Secure)" -ForegroundColor Green
        } else {
            Write-Host "  [!] MISMATCH: $ValueName = $($Actual) (Expected: $($ExpectedValue))" -ForegroundColor Red
            $script:Vulnerable = $true
        }
    } else {
        Write-Host "  [!] MISSING VALUE: $ValueName (Expected: $($ExpectedValue))" -ForegroundColor Red
        $script:Vulnerable = $true
    }
} else {
    Write-Host "  [!] MISSING KEY: $TargetKey" -ForegroundColor Red
    $script:Vulnerable = $true
}

$TargetKey = "HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\Security"
$ValueName = "WarningLevel"
$ExpectedValue = 90
if (Test-Path -Path $TargetKey) {
    $Prop = Get-ItemProperty -Path $TargetKey -Name $ValueName -ErrorAction SilentlyContinue
    if ($null -ne $Prop) {
        $Actual = $Prop.$ValueName
        if ($Actual -eq $ExpectedValue) {
            Write-Host "  [+] $ValueName = $($Actual) (Secure)" -ForegroundColor Green
        } else {
            Write-Host "  [!] MISMATCH: $ValueName = $($Actual) (Expected: $($ExpectedValue))" -ForegroundColor Red
            $script:Vulnerable = $true
        }
    } else {
        Write-Host "  [!] MISSING VALUE: $ValueName (Expected: $($ExpectedValue))" -ForegroundColor Red
        $script:Vulnerable = $true
    }
} else {
    Write-Host "  [!] MISSING KEY: $TargetKey" -ForegroundColor Red
    $script:Vulnerable = $true
}

if ($script:Vulnerable) {
    Write-Host "Audit Result: VULNERABLE" -ForegroundColor Red
    exit 1
} else {
    Write-Host "Audit Result: SECURE" -ForegroundColor Green
    exit 0
}
```

---

### Option C: Manual Verification

Verify the applied policy settings via administrative command prompt:
```cmd
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v ScreenSaverGracePeriod
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v SafeDllSearchMode
reg query "HKLM\SYSTEM\CurrentControlSet\Services\Eventlog\Security" /v WarningLevel
```
Expected output:
```text
AutoAdminLogon            REG_SZ       0
ScreenSaverGracePeriod    REG_DWORD    0x5
SafeDllSearchMode         REG_DWORD    0x1
WarningLevel              REG_DWORD    0x5a
```

---

## Sources & Compliance References
* **CIS Benchmark**: CIS Microsoft Windows Client Benchmark: Section 18.5.1, Section 18.5.9, Section 18.5.10, Section 18.5.13
* **Microsoft Security Compliance Toolkit**: MSS (Microsoft Solutions for Security) Baseline Settings
* **ANSSI Active Directory Hardening Guide**: Baseline security parameters for managed Windows environments
* **MITRE ATT&CK**: [T1574.001: DLL Search Order Hijacking](https://attack.mitre.org/techniques/T1574/001/), [T1552.002: Credentials in Registry](https://attack.mitre.org/techniques/T1552/002/), [T1070.001: Clear Windows Event Logs](https://attack.mitre.org/techniques/T1070/001/), [T1200: Hardware Additions](https://attack.mitre.org/techniques/T1200/)
* **Related Controls**: [REQ-END-188: Administrative Templates: Interactive Logon and Credential Display Options](configure-end-at-logon-display-options.md), [REQ-END-200: Administrative Templates: Configure Advanced Event Log Sizes](configure-end-at-event-log-sizes.md)
