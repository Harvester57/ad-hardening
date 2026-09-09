# [REQ-PAW-171] Administrative Templates: MSS System and Session Security Protections for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration.
* **Operating Systems**: Windows 10 Enterprise (1607+) and Windows 11 Enterprise.

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

Privileged Access Workstations (PAWs) are hardened bastion hosts utilized by directory administrators to manage Active Directory domain controllers, Kerberos policies, and enterprise identity databases. Because PAWs operate under maximum privilege conditions, fundamental session security, DLL loading mechanisms, physical console timeouts, and security audit log thresholds must be enforced with zero tolerance for compromise.

### Technical Threat Vectors & PAW Core Subsystem Protection
1. **Strict Prohibition of Automatic Administrative Logon (`AutoAdminLogon = 0`)**: Enabling automatic logon on a PAW would cause the host to automatically boot directly into an active, authenticated administrative session. This exposes the host to immediate physical compromise upon system restart and requires storing the administrative account password in cleartext within the registry (`DefaultPassword`). Disabling automatic logon guarantees that multi-factor authentication (smart card or FIDO2 hardware token) and interactive credential input are strictly enforced at every system boot.
2. **DLL Search-Order Preloading Defense (`SafeDllSearchMode = 1`)**: Tier 0 administrators execute powerful administrative utilities, custom PowerShell management modules, and directory inspection binaries. If Safe DLL Search Mode is inactive, an attacker with file-write permissions to any shared folder or working directory can drop a malicious DLL masquerading as a legitimate Windows system library. When an administrator executes a management binary from that path, the tool loads the malicious DLL with administrative privileges. Safe DLL Search Mode ensures the current working directory is only checked after protected system folders (`%SystemRoot%\System32`, `%SystemRoot%`), neutralizing DLL preloading and hijacking vectors.
3. **Lock Screen Console Seizure Mitigation (`ScreenSaverGracePeriod = 5`)**: When an administrator steps away from a PAW in a secure operations center or data center floor, the screen lock engages after a brief period of inactivity. If a prolonged grace period is permitted, an unauthorized individual could seize physical control of an active Tier 0 session without entering credentials. Enforcing a grace period of 5 seconds or fewer ensures the console requires immediate re-authentication.
4. **Guaranteed Forensics via Security Log Threshold Alerting (`WarningLevel = 90`)**: PAWs generate vital audit logs tracking directory modifications, PowerShell command execution, and authentication events. If an adversary attempts to blind security operations by flooding event logs to force overwrite conditions, setting `WarningLevel = 90` ensures that Windows Event ID 1104 is generated when log capacity reaches 90%. This gives SIEM operations immediate warning to preserve forensic evidence and investigate anomalous volume.

---

## Legacy Impact & Compatibility

* **Operational Impact**: Automatic logons are strictly barred on PAW hardware. Tier 0 administrators must provide smart card PINs or cryptographic tokens at every boot. All native administrative tools (Active Directory Administrative Center, RSAT, PowerShell, Hyper-V Manager) load standard system libraries from secure system directories without disruption.
* **Console Security**: The console locks completely 5 seconds after screen saver engagement, preventing unauthorized physical walk-up access.
* **Forensic Auditing**: Guarantees early warning event generation before security audit logs overwrite active data.
* **Rollout Recommendations**: Mandatory for all PAW deployment rings; apply immediately.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to the PAWs Organizational Unit (e.g., `GPO_Hardening_PAW`).
3. Navigate to:
   ```text
   Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options
   ```
4. Configure the following MSS policies:
   * **MSS: (AutoAdminLogon) Enable Automatic Logon**: Set to `Disabled`
   * **MSS: (SafeDllSearchMode) Enable Safe DLL search mode**: Set to `Enabled`
   * **MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires**: Set to `Enabled: 5 or fewer seconds`
   * **MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning**: Set to `Enabled: 90% or less`
5. Click **Apply**, then click **OK** for each policy.
6. Link the GPO to the dedicated PAW Organizational Unit and verify policy replication across all Domain Controllers.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to configure the administrative template registry values:

[Download Script: Configure-PawAtMssSystemProtections.ps1](../implementation_scripts/Configure-PawAtMssSystemProtections.ps1)

```powershell
#Configure-PawAtMssSystemProtections.ps1
# Description: Configures Administrative Templates: MSS System and Session Security Protections for PAWs.

Write-Host "Configuring Administrative Templates: MSS System and Session Security Protections for PAWs..." -ForegroundColor Cyan

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

Write-Host "[+] Administrative Templates: MSS System and Session Security Protections for PAWs applied successfully." -ForegroundColor Green
```

*To verify the configuration:*

[Download Script: Get-PawAtMssSystemProtectionsStatus.ps1](../audit_scripts/Get-PawAtMssSystemProtectionsStatus.ps1)

```powershell
#Get-PawAtMssSystemProtectionsStatus.ps1
# Description: Audits Administrative Templates: MSS System and Session Security Protections for PAWs.

Write-Host "--- Auditing Administrative Templates: MSS System and Session Security Protections for PAWs ---" -ForegroundColor Cyan
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
* **ANSSI Active Directory Hardening Guide**: Section 3.4 - PAW Isolation and Administrative Endpoint Hardening
* **MITRE ATT&CK**: [T1574.001: DLL Search Order Hijacking](https://attack.mitre.org/techniques/T1574/001/), [T1552.002: Credentials in Registry](https://attack.mitre.org/techniques/T1552/002/), [T1070.001: Clear Windows Event Logs](https://attack.mitre.org/techniques/T1070/001/), [T1200: Hardware Additions](https://attack.mitre.org/techniques/T1200/)
* **Related Controls**: [REQ-PAW-177: Administrative Templates: Interactive Logon and Credential Display Options for PAWs](configure-paw-at-logon-display-options.md), [REQ-PAW-189: Administrative Templates: Configure Advanced Event Log Sizes for PAWs](configure-paw-at-event-log-sizes.md)
