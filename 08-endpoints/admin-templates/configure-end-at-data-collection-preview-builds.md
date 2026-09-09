# [REQ-END-198] Administrative Templates: Diagnostic Data Collection and Preview Builds Restrictions

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers.
* **Operating Systems**: Windows 10 (and above) Enterprise/Professional, Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: High
* **Policy Category**: Computer Configuration -> Administrative Templates -> Windows Components -> Data Collection and Preview Builds
* **Policy Settings**:
  * Disable OneSettings Downloads
  * Do not show feedback notifications
  * Enable OneSettings Auditing
  * Limit Diagnostic Log Collection
  * Limit Dump Collection
  * Toggle user control over Insider builds (Preview Builds)
* **Supported On**: Windows 10 (Version 1703) or Windows Server 2016 and above
* **Registry Keys & Values**:
  * `HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection\DisableOneSettingsDownloads` = `1` (REG_DWORD)
  * `HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection\DoNotShowFeedbackNotifications` = `1` (REG_DWORD)
  * `HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection\EnableOneSettingsAuditing` = `1` (REG_DWORD)
  * `HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection\LimitDiagnosticLogCollection` = `1` (REG_DWORD)
  * `HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection\LimitDumpCollection` = `1` (REG_DWORD)
  * `HKLM\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds\AllowBuildPreview` = `0` (REG_DWORD)
* **Vulnerability References**: MITRE ATT&CK: T1003 (OS Credential Dumping), T1020 (Automated Exfiltration), T1082 (System Information Discovery), T1499 (Endpoint Denial of Service)

---

## Rationale

The Windows Diagnostic Data Collection infrastructure collects system health, performance metrics, crash dumps, and telemetry data for transmission to Microsoft cloud services. Concurrently, the Windows Insider Program allows systems to receive pre-release operating system builds. In managed enterprise environments, unrestricted diagnostic data collection and preview builds introduce serious data leakage and operational stability risks.

### Technical Threat Vectors & Credential Exposure
1. **Credential Exposure via Memory Crash Dumps & Diagnostic Logs**: When an application or system component encounters an unhandled exception, Windows can generate memory dumps and verbose Event Tracing for Windows (ETW) logs. Process memory dumps capture the exact RAM contents of the failing process, which frequently contain unencrypted authentication secrets, session tokens, Kerberos ticket-granting tickets (TGTs), private TLS keys, database connection strings, and sensitive customer data. Permitting unconstrained crash dump collection (`LimitDumpCollection = 0`) risks uploading memory dumps containing plain-text credentials to external telemetry endpoints.
2. **Dynamic Cloud Reconfiguration via OneSettings**: Microsoft OneSettings is a cloud-driven targeted configuration service. It allows Microsoft cloud endpoints to dynamically modify diagnostic configurations, sample rates, and experimental telemetry features on endpoints without requiring Group Policy updates or operating system patches. Disabling OneSettings downloads (`DisableOneSettingsDownloads = 1`) guarantees that local Group Policy remains the authoritative source of configuration, preventing third-party dynamic overrides.
3. **Auditing OneSettings Configuration Attempts**: Enabling OneSettings auditing (`EnableOneSettingsAuditing = 1`) logs all attempts by Windows to query or apply cloud configuration updates to the `Microsoft-Windows-DataCollection/Operational` event channel, providing security visibility into telemetry behaviors.
4. **Pre-Release Code & Instability via Preview Builds**: Permitting users to enroll enterprise endpoints into Windows Insider Preview builds (`AllowBuildPreview = 1`) deploys unvetted, pre-release kernel drivers and operating system updates. Untested preview builds frequently introduce security regressions, cause incompatibilities with Endpoint Detection and Response (EDR) sensors or antivirus agents, and violate enterprise change management frameworks.
5. **Suppression of Distracting Feedback Prompts**: Windows feedback prompts ("How likely are you to recommend Windows?") interrupt user workflows and encourage employees to submit subjective feedback, diagnostic notes, or desktop screenshots that may inadvertently contain proprietary enterprise information.

---

## Legacy Impact & Compatibility

* **Operational Impact**: Users cannot enroll endpoints in Windows Insider preview builds. Feedback prompts are completely suppressed. Crash reporting is restricted to minimal, sanitized crash headers rather than full memory dumps. Enterprise line-of-business software, standard monthly quality updates (B-release patches), and corporate software distributions remain fully unaffected.
* **Security & Privacy Assurance**: Significantly reduces the risk of corporate credentials or memory contents being transmitted to external telemetry cloud services.
* **Network Impact**: Lowers outbound bandwidth consumption and reduces HTTP/HTTPS connections to Microsoft telemetry endpoints (`v10.events.data.microsoft.com`, `watson.telemetry.microsoft.com`).
* **Rollout Recommendations**: High security priority. Apply across all workstations, servers, and VDI pools immediately.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to workstations and member servers (e.g., `GPO_Hardening_Endpoints`).
3. Navigate to:
   ```text
   Computer Configuration\Policies\Administrative Templates\Windows Components\Data Collection and Preview Builds
   ```
4. Configure the following policies:
   * **Disable OneSettings Downloads**: Set to `Enabled`
   * **Do not show feedback notifications**: Set to `Enabled`
   * **Enable OneSettings Auditing**: Set to `Enabled`
   * **Limit Diagnostic Log Collection**: Set to `Enabled`
   * **Limit Dump Collection**: Set to `Enabled`
   * **Toggle user control over Insider builds**: Set to `Disabled`
5. Click **Apply**, then click **OK** for each policy.
6. Link the GPO to the appropriate Organizational Unit (OU) and verify policy replication across all domain controllers.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to configure the administrative template registry values:

[Download Script: Configure-EndAtDataCollectionPreviewBuilds.ps1](../implementation_scripts/Configure-EndAtDataCollectionPreviewBuilds.ps1)

```powershell
#Configure-EndAtDataCollectionPreviewBuilds.ps1
# Description: Configures Administrative Templates: Diagnostic Data Collection and Preview Builds Restrictions.

Write-Host "Configuring Administrative Templates: Diagnostic Data Collection and Preview Builds Restrictions..." -ForegroundColor Cyan

if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DisableOneSettingsDownloads" -Value 1 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Value 1 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "EnableOneSettingsAuditing" -Value 1 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "LimitDiagnosticLogCollection" -Value 1 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "LimitDumpCollection" -Value 1 -Type DWord -Force

if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -Name "AllowBuildPreview" -Value 0 -Type DWord -Force

Write-Host "[+] Administrative Templates: Diagnostic Data Collection and Preview Builds Restrictions applied successfully." -ForegroundColor Green
```

*To verify the configuration:*

[Download Script: Get-EndAtDataCollectionPreviewBuildsStatus.ps1](../audit_scripts/Get-EndAtDataCollectionPreviewBuildsStatus.ps1)

```powershell
#Get-EndAtDataCollectionPreviewBuildsStatus.ps1
# Description: Audits Administrative Templates: Diagnostic Data Collection and Preview Builds Restrictions.

Write-Host "--- Auditing Administrative Templates: Diagnostic Data Collection and Preview Builds Restrictions ---" -ForegroundColor Cyan
$script:Vulnerable = $false

$TargetKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
$ValueName = "DisableOneSettingsDownloads"
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

$TargetKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
$ValueName = "DoNotShowFeedbackNotifications"
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

$TargetKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
$ValueName = "EnableOneSettingsAuditing"
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

$TargetKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
$ValueName = "LimitDiagnosticLogCollection"
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

$TargetKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
$ValueName = "LimitDumpCollection"
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

$TargetKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds"
$ValueName = "AllowBuildPreview"
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
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /s
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" /v AllowBuildPreview
```
Verify the expected DWORD values:
```text
DisableOneSettingsDownloads     REG_DWORD    0x1
DoNotShowFeedbackNotifications  REG_DWORD    0x1
EnableOneSettingsAuditing       REG_DWORD    0x1
LimitDiagnosticLogCollection    REG_DWORD    0x1
LimitDumpCollection             REG_DWORD    0x1
AllowBuildPreview               REG_DWORD    0x0
```

---

## Sources & Compliance References
* **CIS Benchmark**: CIS Microsoft Windows Client Benchmark: Sections 18.10.16.3, 18.10.16.4, 18.10.16.5, 18.10.16.6, 18.10.16.7, 18.10.16.8
* **Microsoft Security Baseline**: Windows 10 and Windows 11 Security Baseline - Data Collection and Preview Builds
* **ANSSI Active Directory Hardening Guide**: Baseline security parameters for managed Windows environments
* **MITRE ATT&CK**: [T1003: OS Credential Dumping](https://attack.mitre.org/techniques/T1003/), [T1020: Automated Exfiltration](https://attack.mitre.org/techniques/T1020/), [T1082: System Information Discovery](https://attack.mitre.org/techniques/T1082/), [T1499: Endpoint Denial of Service](https://attack.mitre.org/techniques/T1499/)
* **Related Controls**: [REQ-END-186: Administrative Templates: Restrict Internet Communication](configure-end-at-internet-communication.md), [REQ-END-209: Administrative Templates: Windows Update Enterprise Delivery and Deferral Policies](configure-end-at-windows-update-policies.md)
