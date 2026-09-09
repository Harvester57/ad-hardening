# [REQ-PAW-198] Administrative Templates: Windows Update Deferral and Automatic Installation Policies for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration.
* **Operating Systems**: Windows 10 Enterprise (1607+) and Windows 11 Enterprise.

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

Privileged Access Workstations (PAWs) host the most sensitive interactive sessions and management credentials across the entire enterprise directory structure. Because PAWs are high-value targets for sophisticated adversaries seeking lateral movement into Active Directory Domain Controllers, applying cumulative security patches without latency is vital to system survival.

### Technical Threat Vectors & PAW Patch Assurance
1. **Immediate Remediation of Known Vulnerabilities (`DeferQualityUpdatesPeriodInDays = 0`)**: Cumulative quality updates address critical vulnerabilities in core Windows subsystems, including the Windows kernel, LSASS, Remote Procedure Call (RPC), Kerberos authentication packages, and cryptographic minidrivers. Deferring quality updates by 0 days ensures that PAW hosts retrieve and stage security patches immediately upon availability, drastically shrinking the exploitation window against weaponized CVE exploits.
2. **Elimination of Administrative Update Deferral (`SetDisablePauseUXAccess = 1`)**: Tier 0 operators frequently manage demanding operational workloads and may be tempted to click "Pause updates" to avoid scheduled reboots. Allowing updates to be paused on a PAW risks leaving the management plane exposed to public exploits for weeks. Disabling UX pause controls ensures that security patch installation is non-negotiable and deterministic.
3. **Mandatory Restart Enforcement for Kernel Patch Activation (`NoAutoRebootWithLoggedOnUsers = 0`)**: Security patches that fix memory-resident DLLs, RPC runtimes, and kernel drivers cannot complete their installation until the host reboots. If a disconnected or locked administrative session halts the reboot process, the PAW remains vulnerable despite patches being staged on disk. Setting this policy to `0` (Disabled in GPO) allows automated reboots during off-hours maintenance windows to finalize patch activation.
4. **Controlled Feature Update Lifecycle (`DeferFeatureUpdatesPeriodInDays = 180`)**: Major Windows feature updates introduce architectural modifications and updated driver frameworks. Deferring feature upgrades by 180 days protects Tier 0 administrative tooling (RSAT, smart card drivers, hardware token software, MMC snap-ins) from regression-induced failures while ensuring the operating system remains within supported enterprise servicing branches.
5. **Absolute Prohibition of Preview Channel Builds (`ManagePreviewBuildsPolicyValue = 1`)**: Enrolling a PAW in Windows Insider preview builds introduces untested pre-release code into Tier 0. Pre-release builds violate isolation and verification principles and must never execute on administrative hardware.

---

## Legacy Impact & Compatibility

* **Operational Impact**: Tier 0 administrators cannot pause updates. Automated reboots occur during off-hours maintenance windows (e.g., 03:00 AM) to complete patch installations.
* **Compatibility**: 180-day feature update deferral preserves administrative tool compatibility (RSAT, Active Directory Administrative Center, PowerShell modules). Quality updates are applied without deferral.
* **Network & WSUS Architecture**: PAWs in isolated management VLANs retrieve updates from internal, dedicated Tier 0 WSUS servers or secure update relays.
* **Rollout Recommendations**: Mandatory for all PAWs; coordinate with directory administration teams regarding designated daily maintenance reboot windows.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to the PAWs Organizational Unit (e.g., `GPO_Hardening_PAW`).
3. Configure the following policies:

* Navigate to: `Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Update`
  * **Remove access to 'Pause updates' feature**: Set to `Enabled`
  * **Manage preview builds**: Set to `Disabled`
  * **Select when Preview Builds and Feature Updates are received**: Set to `Enabled`, select **Semi-Annual Channel**, and set deferral to `180` days
  * **Select when Quality Updates are received**: Set to `Enabled`, set deferral to `0` days
* Navigate to: `Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Update\Manage end user experience`
  * **Configure Automatic Updates**: Set to `Enabled`, select option **4 - Auto download and schedule the install**, set scheduled install day to `0 - Every day`, and configure a suitable maintenance hour (e.g., `03:00`)
  * **No auto-restart with logged on users for scheduled automatic updates installations**: Set to `Disabled`

4. Link the GPO to the dedicated PAW Organizational Unit and verify replication across all Domain Controllers.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to configure the administrative template registry values:

[Download Script: Configure-PawAtWindowsUpdatePolicies.ps1](../implementation_scripts/Configure-PawAtWindowsUpdatePolicies.ps1)

```powershell
#Configure-PawAtWindowsUpdatePolicies.ps1
# Description: Configures Administrative Templates: Windows Update Deferral and Automatic Installation Policies for PAWs.

Write-Host "Configuring Administrative Templates: Windows Update Deferral and Automatic Installation Policies for PAWs..." -ForegroundColor Cyan

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

Write-Host "[+] Administrative Templates: Windows Update Deferral and Automatic Installation Policies for PAWs applied successfully." -ForegroundColor Green
```

*To verify the configuration:*

[Download Script: Get-PawAtWindowsUpdatePoliciesStatus.ps1](../audit_scripts/Get-PawAtWindowsUpdatePoliciesStatus.ps1)

```powershell
#Get-PawAtWindowsUpdatePoliciesStatus.ps1
# Description: Audits Administrative Templates: Windows Update Deferral and Automatic Installation Policies for PAWs.

Write-Host "--- Auditing Administrative Templates: Windows Update Deferral and Automatic Installation Policies for PAWs ---" -ForegroundColor Cyan
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
* **ANSSI Active Directory Hardening Guide**: Section 3.4 - PAW Isolation and Administrative Endpoint Hardening
* **MITRE ATT&CK**: [T1190: Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/), [T1068: Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/), [T1210: Exploitation of Remote Services](https://attack.mitre.org/techniques/T1210/), [T1562.001: Impair Defenses: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/)
* **Related Controls**: [REQ-PAW-187: Administrative Templates: Diagnostic Data Collection and Preview Builds Restrictions for PAWs](configure-paw-at-data-collection-preview-builds.md), [REQ-PAW-175: Administrative Templates: Restrict Internet Communication for PAWs](configure-paw-at-internet-communication.md)
