# [REQ-END-184] Administrative Templates: Enforce Group Policy Background Processing

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers.
* **Operating Systems**: Windows 10 (and above) Enterprise/Professional, Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: High
* **Policy Category**: Computer Configuration -> Administrative Templates -> System -> Group Policy
* **Policy Settings**:
  * Configure registry policy processing
  * Configure security policy processing
* **Supported On**: Windows 2000 or Windows Server 2003 and above
* **Registry Keys & Client-Side Extension (CSE) GUIDs**:
  * Registry Extension: `HKLM\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}`
  * Security Extension: `HKLM\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}`
* **Registry Values**:
  * `NoBackgroundPolicy` = `0` (REG_DWORD, Process policies during periodic background refresh)
  * `NoGPOListChanges` = `0` (REG_DWORD, Process and reapply policies even if GPOs have not changed)
* **Vulnerability References**: MITRE ATT&CK: T1562.001 (Impair Defenses: Disable or Modify Tools), T1112 (Modify Registry), T1484.001 (Group Policy Modification)

---

## Rationale

The Windows Group Policy service (`gpsvc`) manages operating system and security configurations through Client-Side Extensions (CSEs). To minimize network overhead and processing latency, the default Windows Group Policy engine implements an optimization check: during periodic background refresh cycles (every 90 minutes with a randomized 30-minute delta), CSEs compare the local GPO version with the Active Directory SYSVOL version. If the GPO version has not incremented, the CSE skips applying settings.

### Technical Threat Vectors & Anti-Tampering Defense
1. **Remediating Local Defense Impairment & Registry Tampering**: Threat actors, living-off-the-land techniques, and malware frequently tamper with local registry values to weaken defenses (e.g., disabling Windows Defender, downgrading LSA protection, clearing audit policies, or re-enabling insecure legacy protocols). Under default Windows behavior, once an attacker modifies a hardened registry setting, the machine remains vulnerable indefinitely—even across background refresh cycles—because the central GPO version has not changed. Enforcing `NoGPOListChanges = 0` forces the Registry and Security CSEs to re-read and overwrite local settings during every background cycle, ensuring that unauthorized registry modifications are automatically reverted to the enterprise security baseline.
2. **Eliminating Configuration Drift**: Administrative configuration drift occurs when local IT staff make temporary modifications during troubleshooting or software deployment and neglect to restore original parameters. Continuous background enforcement ensures that endpoints deterministically converge back to corporate security baselines.
3. **Background Processing Enforcement (`NoBackgroundPolicy = 0`)**: Some legacy or degraded configurations restrict policy processing strictly to computer boot or user interactive logon. Enforcing background processing ensures that workstations and servers continuously refresh and validate their security posture without requiring machine restarts.
4. **Resilience Against Ransomware Pre-Encryption Steps**: Many modern ransomware families attempt to disable local defense mechanisms prior to encrypting volumes. Continuous background policy re-enforcement continually asserts security controls, limiting the attacker's window of opportunity.

---

## Legacy Impact & Compatibility

* **Operational Impact**: Negligible CPU and disk I/O increase during the 90-minute background Group Policy refresh cycle. The Group Policy service reads locally cached security templates (`Secedit.sdb`) and registry policies (`Registry.pol`), resulting in lightweight execution that is imperceptible to users.
* **Administrative Impact**: Local administrators cannot permanently override corporate baseline settings; any manual registry modifications to hardened parameters will be overwritten during the next refresh cycle.
* **Network Impact**: Zero increase in network bandwidth, as the policy utilizes cached local policies when Active Directory versions match.
* **Rollout Recommendations**: High security benefit with virtually zero operational risk; deploy across all workstations and member servers.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to workstations and member servers (e.g., `GPO_Hardening_Endpoints`).
3. Navigate to:
   ```text
   Computer Configuration\Policies\Administrative Templates\System\Group Policy
   ```
4. Double-click **Configure registry policy processing**:
   * Set to **Enabled**.
   * Check **Process even if the Group Policy objects have not changed**.
   * Uncheck **Do not apply during periodic background processing**.
5. Double-click **Configure security policy processing**:
   * Set to **Enabled**.
   * Check **Process even if the Group Policy objects have not changed**.
   * Uncheck **Do not apply during periodic background processing**.
6. Click **Apply**, then click **OK** for both policies.
7. Link the GPO to the appropriate Organizational Unit (OU) and verify policy replication across all domain controllers.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to configure the administrative template registry values:

[Download Script: Configure-EndAtGpProcessing.ps1](../implementation_scripts/Configure-EndAtGpProcessing.ps1)

```powershell
#Configure-EndAtGpProcessing.ps1
# Description: Configures Administrative Templates: Enforce Group Policy Background Processing.

Write-Host "Configuring Administrative Templates: Enforce Group Policy Background Processing..." -ForegroundColor Cyan

if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" -Name "NoBackgroundPolicy" -Value 0 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" -Name "NoGPOListChanges" -Value 0 -Type DWord -Force

if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}" -Name "NoBackgroundPolicy" -Value 0 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}" -Name "NoGPOListChanges" -Value 0 -Type DWord -Force

Write-Host "[+] Administrative Templates: Enforce Group Policy Background Processing applied successfully." -ForegroundColor Green
```

*To verify the configuration:*

[Download Script: Get-EndAtGpProcessingStatus.ps1](../audit_scripts/Get-EndAtGpProcessingStatus.ps1)

```powershell
#Get-EndAtGpProcessingStatus.ps1
# Description: Audits Administrative Templates: Enforce Group Policy Background Processing.

Write-Host "--- Auditing Administrative Templates: Enforce Group Policy Background Processing ---" -ForegroundColor Cyan
$script:Vulnerable = $false

$TargetKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}"
$ValueName = "NoBackgroundPolicy"
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

$TargetKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}"
$ValueName = "NoGPOListChanges"
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

$TargetKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}"
$ValueName = "NoBackgroundPolicy"
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

$TargetKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}"
$ValueName = "NoGPOListChanges"
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
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" /s
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}" /s
```
Verify that `NoBackgroundPolicy` and `NoGPOListChanges` are present and set to `0x0`.

---

## Sources & Compliance References
* **CIS Benchmark**: CIS Microsoft Windows Client Benchmark: Section 18.9.31.2, Section 18.9.31.3
* **Microsoft Security Baseline**: Windows 10 and Windows 11 Security Baseline - Group Policy Client-Side Extension Processing
* **ANSSI Active Directory Hardening Guide**: Baseline security parameters for managed Windows environments
* **MITRE ATT&CK**: [T1562.001: Impair Defenses: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/), [T1112: Modify Registry](https://attack.mitre.org/techniques/T1112/), [T1484.001: Group Policy Modification](https://attack.mitre.org/techniques/T1484/001/)
* **Related Controls**: [REQ-END-182: Administrative Templates: MSS System and Session Security Protections](configure-end-at-mss-system-protections.md), [REQ-END-188: Administrative Templates: Interactive Logon and Credential Display Options](configure-end-at-logon-display-options.md)
