# [REQ-END-209] Administrative Templates: Windows Update Deferral and Automatic Installation Policies

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers.
* **Operating Systems**: Windows 10 (and above) Enterprise/Professional, Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: High
* **Policy Category**: Computer Configuration -> Administrative Templates -> Windows Components -> Windows Update
* **Policy Settings**:
  * Remove access to 'Pause updates' feature
  * Manage preview builds
  * Select when Preview Builds and Feature Updates are received
  * Select when Quality Updates are received
  * Configure Automatic Updates
  * No auto-restart with logged on users for scheduled automatic updates installations
* **Supported On**: Windows 10 (Version 1607) or Windows Server 2016 and above
* **Registry Keys & Values**:
  * `HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\SetDisablePauseUXAccess` = `1` (REG_DWORD)
  * `HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\ManagePreviewBuildsPolicyValue` = `1` (REG_DWORD)
  * `HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\DeferFeatureUpdates` = `1` (REG_DWORD)
  * `HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\DeferFeatureUpdatesPeriodInDays` = `180` (REG_DWORD)
  * `HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\DeferQualityUpdates` = `1` (REG_DWORD)
  * `HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\DeferQualityUpdatesPeriodInDays` = `0` (REG_DWORD)
  * `HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\NoAutoRebootWithLoggedOnUsers` = `0` (REG_DWORD)
  * `HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\ScheduledInstallDay` = `0` (REG_DWORD, Every day)
* **Vulnerability References**: MITRE ATT&CK: T1190 (Exploit Public-Facing Application), T1068 (Exploitation for Privilege Escalation), T1210 (Exploitation of Remote Services), T1562.001 (Impair Defenses: Disable or Modify Tools)

---

## Rationale

Windows Update is the primary defense mechanism against known Common Vulnerabilities and Exposures (CVEs), remote code execution exploits, and privilege escalation vulnerabilities. In unhardened environments, default update policies allow users to pause updates, postpone reboots, or enroll in experimental preview builds, directly exposing the enterprise network to preventable exploitation.

### Technical Threat Vectors & Vulnerability Remediation
1. **Closing the Vulnerability Exposure Window (`DeferQualityUpdatesPeriodInDays = 0`)**: Quality updates represent monthly cumulative security patches addressing actively exploited zero-day vulnerabilities and critical security flaws. Setting the quality update deferral period to 0 days ensures that client systems and member servers retrieve and stage security patches immediately upon approval or public release, minimizing the window of vulnerability against automated exploit kits and network worms.
2. **Preventing User Deferral of Critical Security Fixes (`SetDisablePauseUXAccess = 1`)**: Standard Windows installations permit interactive users to pause updates for up to 35 days with a single click. In corporate environments, users routinely pause updates to avoid reboots or temporary performance overhead, leaving machines unpatched against high-severity exploits. Removing access to the 'Pause updates' control guarantees that corporate patching schedules cannot be overridden by end users.
3. **Ensuring Kernel Patch Completion via Automated Restarts (`NoAutoRebootWithLoggedOnUsers = 0`)**: Many critical Windows vulnerabilities (such as kernel memory corruptions, LSASS vulnerabilities, and RPC/SMB flaws) require an operating system restart to replace locked system binaries and apply kernel-mode drivers. If `NoAutoRebootWithLoggedOnUsers` is enabled (`1`), any user who leaves a disconnected or locked session indefinitely halts the reboot process, leaving the system in a vulnerable half-patched state. Setting this policy to `0` (Disabled in GPO) allows the Windows Update client to perform scheduled reboots during maintenance hours, ensuring patch application completes.
4. **Balancing Stability and Compatibility for Feature Updates (`DeferFeatureUpdatesPeriodInDays = 180`)**: Feature updates deliver major operating system version upgrades. Unlike monthly security fixes, feature updates introduce substantial architectural and UI changes that may disrupt line-of-business (LOB) software, third-party security agents, and VPN clients. Deferring feature updates by 180 days provides IT and security teams adequate time to pilot, validate, and certify compatibility before enterprise-wide distribution.
5. **Prohibiting Unstable Preview Builds (`ManagePreviewBuildsPolicyValue = 1`)**: Disabling preview builds guarantees that endpoints only execute production-grade, cryptographically validated Windows binaries, preventing operational instability and untested security configurations.

---

## Legacy Impact & Compatibility

* **Operational Impact**: Users cannot pause updates in the Windows Settings UI. Machines will automatically restart during scheduled maintenance windows (e.g., 03:00 AM) if pending updates require a reboot.
* **Compatibility**: 180-day feature update deferral shields line-of-business applications from unexpected operating system version changes while 0-day quality update deferral ensures zero delay in receiving critical security patches.
* **Network Impact**: Bandwidth consumption is controlled via corporate WSUS, Microsoft Endpoint Configuration Manager (MECM), or Delivery Optimization.
* **Rollout Recommendations**: High priority; deploy across all Tier 2 workstations and member servers with clear communication regarding scheduled reboot windows.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to workstations and member servers (e.g., `GPO_Hardening_Endpoints`).
3. Configure the following policies:

* Navigate to: `Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Update`
  * **Remove access to 'Pause updates' feature**: Set to `Enabled`
  * **Manage preview builds**: Set to `Disabled`
  * **Select when Preview Builds and Feature Updates are received**: Set to `Enabled`, select **Semi-Annual Channel**, and set deferral to `180` days
  * **Select when Quality Updates are received**: Set to `Enabled`, set deferral to `0` days
* Navigate to: `Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Update\Manage end user experience`
  * **Configure Automatic Updates**: Set to `Enabled`, select option **4 - Auto download and schedule the install**, set scheduled install day to `0 - Every day`, and configure a suitable maintenance hour (e.g., `03:00`)
  * **No auto-restart with logged on users for scheduled automatic updates installations**: Set to `Disabled`

4. Link the GPO to the appropriate Organizational Unit (OU) and verify policy replication across all domain controllers.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to configure the administrative template registry values:

[Download Script: Configure-EndAtWindowsUpdatePolicies.ps1](../implementation_scripts/Configure-EndAtWindowsUpdatePolicies.ps1)

```powershell
#Configure-EndAtWindowsUpdatePolicies.ps1
# Description: Configures Administrative Templates: Windows Update Deferral and Automatic Installation Policies.

Write-Host "Configuring Administrative Templates: Windows Update Deferral and Automatic Installation Policies..." -ForegroundColor Cyan

if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "SetDisablePauseUXAccess" -Value 1 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ManagePreviewBuildsPolicyValue" -Value 1 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferFeatureUpdates" -Value 1 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferFeatureUpdatesPeriodInDays" -Value 180 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferQualityUpdates" -Value 1 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferQualityUpdatesPeriodInDays" -Value 0 -Type DWord -Force

if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoRebootWithLoggedOnUsers" -Value 0 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "ScheduledInstallDay" -Value 0 -Type DWord -Force

Write-Host "[+] Administrative Templates: Windows Update Deferral and Automatic Installation Policies applied successfully." -ForegroundColor Green
```

*To verify the configuration:*

[Download Script: Get-EndAtWindowsUpdatePoliciesStatus.ps1](../audit_scripts/Get-EndAtWindowsUpdatePoliciesStatus.ps1)

```powershell
#Get-EndAtWindowsUpdatePoliciesStatus.ps1
# Description: Audits Administrative Templates: Windows Update Deferral and Automatic Installation Policies.

Write-Host "--- Auditing Administrative Templates: Windows Update Deferral and Automatic Installation Policies ---" -ForegroundColor Cyan
$script:Vulnerable = $false

$TargetKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
$ValueName = "SetDisablePauseUXAccess"
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

$TargetKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
$ValueName = "ManagePreviewBuildsPolicyValue"
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

$TargetKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
$ValueName = "DeferFeatureUpdates"
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

$TargetKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
$ValueName = "DeferFeatureUpdatesPeriodInDays"
$ExpectedValue = 180
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

$TargetKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
$ValueName = "DeferQualityUpdates"
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

$TargetKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
$ValueName = "DeferQualityUpdatesPeriodInDays"
$ExpectedValue = 0
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

$TargetKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
$ValueName = "NoAutoRebootWithLoggedOnUsers"
$ExpectedValue = 0
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

$TargetKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
$ValueName = "ScheduledInstallDay"
$ExpectedValue = 0
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
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /s
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /s
```
Verify that all configured values match the defined baseline.

---

## Sources & Compliance References
* **CIS Benchmark**: CIS Microsoft Windows Client Benchmark: Section 18.10.93.1, 18.10.93.2, 18.10.93.3, 18.10.93.4
* **Microsoft Security Baseline**: Windows 10 and Windows 11 Security Baseline - Windows Update
* **ANSSI Active Directory Hardening Guide**: Baseline security parameters for managed Windows environments
* **MITRE ATT&CK**: [T1190: Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/), [T1068: Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/), [T1210: Exploitation of Remote Services](https://attack.mitre.org/techniques/T1210/), [T1562.001: Impair Defenses: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/)
* **Related Controls**: [REQ-END-198: Administrative Templates: Diagnostic Data Collection and Preview Builds Restrictions](configure-end-at-data-collection-preview-builds.md), [REQ-END-186: Administrative Templates: Restrict Internet Communication](configure-end-at-internet-communication.md)
