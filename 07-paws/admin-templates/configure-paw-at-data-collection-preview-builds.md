# [REQ-PAW-187] Administrative Templates: Diagnostic Data Collection and Preview Builds Restrictions for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration.
* **Operating Systems**: Windows 10 Enterprise (1607+) and Windows 11 Enterprise.

---

## Implementation Details
* **Priority**: Critical
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

Privileged Access Workstations (PAWs) are the dedicated administrative bastion hosts for Tier 0 Active Directory Domain Services, enterprise root certification authorities, and identity synchronization infrastructure. Workstations in this tier manage unconstrained directory objects, Kerberos Ticket Granting Service (TGS) sessions, and domain administrator secrets. The default Windows diagnostic telemetry, crash reporting, and preview build mechanisms pose catastrophic security risks to high-assurance Tier 0 environments.

### Technical Threat Vectors & Tier 0 Credential Protection
1. **Tier 0 Credential Dumping via Crash Dumps & ETW Logs**: When an administrative console (such as PowerShell, Active Directory Users and Computers, or an MMC snap-in) or a system service crashes, Windows can capture full or triage memory dumps. Memory dumps of administrative sessions contain raw Tier 0 credentials—including plaintext passwords, Kerberos session keys, NTLM hashes, and DPAPI master keys. Allowing unconstrained memory dump collection (`LimitDumpCollection = 0`) creates localized dump files and triggers automated upload workflows to Microsoft telemetry clouds, risking the external exposure of root directory credentials.
2. **Dynamic Configuration Tampering via OneSettings**: Microsoft OneSettings is an online configuration service designed to dynamically adjust telemetry levels, feature flags, and diagnostic behaviors over the cloud. On a PAW, the operating system configuration baseline must remain static, cryptographically verified, and strictly under internal enterprise administrative control. Permitting OneSettings downloads allows remote cloud services to modify diagnostic and telemetry parameters on a Tier 0 workstation, subverting local security baselines.
3. **Auditing Unauthorized Cloud Ingestion Attempts**: Enabling OneSettings auditing ensures that any anomalous network connection or telemetry invocation attempt by the Windows operating system is captured in the local event log (`Microsoft-Windows-DataCollection/Operational`), providing Tier 0 SOC teams with immediate visibility into potential telemetry bypasses.
4. **Prohibition of Unvetted Code via Insider Preview Builds**: Windows Insider builds contain experimental kernel revisions, unvetted device drivers, and incomplete security patches. Enrolling a PAW in preview channels introduces software instabilities, voids compliance baselines, and risks breaking core Tier 0 security agents (such as hardware-enforced isolation, credential guard, and EDR agents).
5. **Suppression of Distracting Feedback Mechanisms**: PAWs must operate without user-facing distractions, promotional prompts, or consumer feedback dialogues that could tempt administrators into transmitting diagnostic screenshots or environment metadata.

Limiting diagnostic and dump collections to absolute minimum sanitized headers, disabling OneSettings downloads, and permanently prohibiting preview builds ensures that Tier 0 administrative secrets remain strictly contained.

---

## Legacy Impact & Compatibility

* **Operational Impact**: Enrollment in Windows Insider preview channels is blocked. Feedback notifications are completely suppressed. Memory crash dumps are restricted to minimal headers with sensitive memory pages excluded. Core Tier 0 administration tools (RSAT, PowerShell, Hyper-V management, Active Directory Administrative Center) operate without interruption.
* **Security Assurance**: Eliminates the catastrophic risk of Tier 0 domain credentials or administrative session keys leaking via automated crash reporting or telemetry pipelines.
* **Network & Firewall Impact**: Eliminates background HTTPS connections to Microsoft telemetry endpoints (`*.events.data.microsoft.com`, `*.telemetry.microsoft.com`).
* **Rollout Recommendations**: Mandatory baseline setting for all PAW deployment rings; apply immediately.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to the PAWs Organizational Unit (e.g., `GPO_Hardening_PAW`).
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
6. Link the GPO to the dedicated PAW Organizational Unit and verify policy replication across all Domain Controllers.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to configure the administrative template registry values:

[Download Script: Configure-PawAtDataCollectionPreviewBuilds.ps1](../implementation_scripts/Configure-PawAtDataCollectionPreviewBuilds.ps1)

```powershell
#Configure-PawAtDataCollectionPreviewBuilds.ps1
# Description: Configures Administrative Templates: Diagnostic Data Collection and Preview Builds Restrictions for PAWs.

Write-Host "Configuring Administrative Templates: Diagnostic Data Collection and Preview Builds Restrictions for PAWs..." -ForegroundColor Cyan

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

Write-Host "[+] Administrative Templates: Diagnostic Data Collection and Preview Builds Restrictions for PAWs applied successfully." -ForegroundColor Green
```

*To verify the configuration:*

[Download Script: Get-PawAtDataCollectionPreviewBuildsStatus.ps1](../audit_scripts/Get-PawAtDataCollectionPreviewBuildsStatus.ps1)

```powershell
#Get-PawAtDataCollectionPreviewBuildsStatus.ps1
# Description: Audits Administrative Templates: Diagnostic Data Collection and Preview Builds Restrictions for PAWs.

Write-Host "--- Auditing Administrative Templates: Diagnostic Data Collection and Preview Builds Restrictions for PAWs ---" -ForegroundColor Cyan
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
* **ANSSI Active Directory Hardening Guide**: Section 3.4 - PAW Isolation and Administrative Endpoint Hardening
* **MITRE ATT&CK**: [T1003: OS Credential Dumping](https://attack.mitre.org/techniques/T1003/), [T1020: Automated Exfiltration](https://attack.mitre.org/techniques/T1020/), [T1082: System Information Discovery](https://attack.mitre.org/techniques/T1082/), [T1499: Endpoint Denial of Service](https://attack.mitre.org/techniques/T1499/)
* **Related Controls**: [REQ-PAW-175: Administrative Templates: Restrict Internet Communication for PAWs](configure-paw-at-internet-communication.md), [REQ-PAW-198: Administrative Templates: Windows Update Delivery and Deferral Policies for PAWs](configure-paw-at-windows-update-policies.md)
