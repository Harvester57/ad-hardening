# [REQ-PAW-173] Administrative Templates: Enforce Group Policy Background Processing for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration.
* **Operating Systems**: Windows 10 Enterprise (1607+) and Windows 11 Enterprise.

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

Privileged Access Workstations (PAWs) are high-security administrative bastion hosts dedicated exclusively to Tier 0 directory services management. Maintaining a deterministic, tamper-resistant system state on PAWs is a foundational requirement of the Microsoft Clean Source and tiering security models.

### Technical Threat Vectors & PAW State Integrity
1. **Automated Remediation of Defense Impairment (`NoGPOListChanges = 0`)**: Attackers gaining localized access to an administrative workstation often attempt to impair defenses by silently modifying security registry keys (e.g., turning off Credential Guard, weakening LSA RunAsPPL protections, disabling AppLocker enforcement, or clearing audit policies). Under default Windows Group Policy behavior, Client-Side Extensions (CSEs) for Registry and Security settings skip background execution if the central GPO version in Active Directory SYSVOL has not changed. This leaves compromised or weakened registry settings active indefinitely. Enforcing `NoGPOListChanges = 0` forces the operating system to overwrite local registry settings with the approved Tier 0 baseline during every background refresh cycle, providing an automated self-healing mechanism against administrative tampering.
2. **Deterministic Baseline Enforcement without Reboots (`NoBackgroundPolicy = 0`)**: Tier 0 administrators frequently keep long-running administrative sessions open across multiple days or weeks. Forcing background processing guarantees that critical security policies and registry restrictions are continuously reapplied throughout active sessions, rather than waiting for a system restart or user logoff.
3. **Elimination of Administrative Configuration Drift**: When performing ad-hoc diagnostics or deploying specialized management packages, administrators might temporarily adjust security settings. Continuous background enforcement ensures that all PAW systems deterministically revert back to the authoritative enterprise baseline within 90 minutes.
4. **Guaranteed Consistency for Registry & Security CSEs**: Applying this policy to both the Registry CSE (`{35378EAC-683F-11D2-A89A-00C04FBBCFA2}`) and the Security Settings CSE (`{827D319E-6EAC-11D2-A4EA-00C04F79F83A}`) ensures comprehensive coverage over administrative templates, local rights assignments, system access permissions, and registry keys.

---

## Legacy Impact & Compatibility

* **Operational Impact**: Negligible CPU and disk I/O impact during background refresh cycles. The Group Policy engine evaluates cached local policies, ensuring that administrative operations (RSAT, PowerShell scripting, Active Directory Administrative Center) experience zero disruption.
* **Administrative Impact**: Temporary manual adjustments made to hardened registry parameters will be automatically reverted during the next 90-minute background cycle.
* **Network Impact**: Zero additional bandwidth utilization on the administrative management network.
* **Rollout Recommendations**: Mandatory baseline setting for all PAW deployment rings; apply immediately.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to the PAWs Organizational Unit (e.g., `GPO_Hardening_PAW`).
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
7. Link the GPO to the dedicated PAW Organizational Unit and verify policy replication across all Domain Controllers.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to configure the administrative template registry values:

[Download Script: Configure-PawAtGpProcessing.ps1](../implementation_scripts/Configure-PawAtGpProcessing.ps1)

```powershell
#Configure-PawAtGpProcessing.ps1
# Description: Configures Administrative Templates: Enforce Group Policy Background Processing for PAWs.

Write-Host "Configuring Administrative Templates: Enforce Group Policy Background Processing for PAWs..." -ForegroundColor Cyan

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

Write-Host "[+] Administrative Templates: Enforce Group Policy Background Processing for PAWs applied successfully." -ForegroundColor Green
```

*To verify the configuration:*

[Download Script: Get-PawAtGpProcessingStatus.ps1](../audit_scripts/Get-PawAtGpProcessingStatus.ps1)

```powershell
#Get-PawAtGpProcessingStatus.ps1
# Description: Audits Administrative Templates: Enforce Group Policy Background Processing for PAWs.

Write-Host "--- Auditing Administrative Templates: Enforce Group Policy Background Processing for PAWs ---" -ForegroundColor Cyan
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
* **ANSSI Active Directory Hardening Guide**: Section 3.4 - PAW Isolation and Administrative Endpoint Hardening
* **MITRE ATT&CK**: [T1562.001: Impair Defenses: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/), [T1112: Modify Registry](https://attack.mitre.org/techniques/T1112/), [T1484.001: Group Policy Modification](https://attack.mitre.org/techniques/T1484/001/)
* **Related Controls**: [REQ-PAW-171: Administrative Templates: MSS System and Session Security Protections for PAWs](configure-paw-at-mss-system-protections.md), [REQ-PAW-177: Administrative Templates: Interactive Logon and Credential Display Options for PAWs](configure-paw-at-logon-display-options.md)
