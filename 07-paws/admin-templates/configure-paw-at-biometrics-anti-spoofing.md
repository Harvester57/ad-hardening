# [REQ-PAW-183] Administrative Templates: Configure Biometrics Enhanced Anti-Spoofing for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration. *(For Tier 2 Client Workstations and Member Servers, refer to baseline [REQ-END-194](../../08-endpoints/admin-templates/configure-end-at-biometrics-anti-spoofing.md)).*
* **Operating Systems**: Windows 10 Enterprise (1607+) and Windows 11 Enterprise.

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**:
  * **Configure enhanced anti-spoofing**:
    * GPO Path: `Computer Configuration\Policies\Administrative Templates\Windows Components\Biometrics\Facial Features\Configure enhanced anti-spoofing` -> **Enabled**
    * Registry Path: `HKLM\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures`
    * Value Name: `EnhancedAntiSpoofing`
    * Value Type: `REG_DWORD`
    * Value Data: `1` (Enabled / Enforce hardware depth and IR liveness)

---

## Rationale
Privileged Access Workstations (PAWs) serve as the highest-trust endpoints within an Active Directory enterprise architecture. Physical access to an unlocked PAW grants direct compromise capability over Tier 0 directory services. If biometric facial verification is utilized for PAW operator logon, it must enforce the highest cryptographic and hardware liveness guarantees.

### 1. Guarding Tier 0 Console Access Against Presentation Attacks
Standard 2D optical facial recognition can be deceived by visual replicas:
* An adversary obtaining physical proximity to an unattended PAW could attempt presentation attacks using high-resolution photographs, video playback on portable screens, or 3D synthetic masks.
* On a PAW, any successful spoof immediately exposes Domain Admin sessions, active RSAT consoles, and Kerberos Ticket Granting Service keys to unauthorized operators.
* Enforcing `EnhancedAntiSpoofing = 1` requires the biometric subsystem to perform rigorous infrared spectral analysis and 3D depth mesh confirmation. Flat images, video screens, and non-living models are unconditionally rejected.

### 2. Ensuring Strict Biometric Sensor Certification
Enforcing enhanced anti-spoofing mandates compliant hardware:
* The Windows Biometric Framework strictly blocks facial logon on devices lacking dedicated near-IR depth sensors certified for enterprise anti-spoofing.
* This guarantees that PAW operators only utilize secure biometric hardware backed by TPM 2.0 key sealing.

### 3. MITRE ATT&CK Mapping
* **T1110 - Brute Force / Biometric Spoofing**: Presentation attacks against Tier 0 administrative workstation locks.
* **T1078 - Valid Accounts**: Unauthorized console access to administrative sessions.

---

## Legacy Impact & Compatibility
* **Operational Impact**: PAWs lacking certified Windows Hello IR cameras will disallow facial recognition configuration. Operators on these machines authenticate using dedicated hardware Smart Cards (PIV/CAC) or FIDO2 hardware keys.
* **Administrative Operations**: No disruption to Tier 0 directory management workflows.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to the PAWs Organizational Unit (e.g., `GPO_Hardening_PAW`).
3. Configure the following policies:

* Navigate to: `Computer Configuration\Policies\Administrative Templates\Windows Components\Biometrics\Facial Features`
  * **Configure enhanced anti-spoofing**: Set to `Enabled`

4. Link the GPO to the PAW Organizational Unit and enforce policy replication using `gpupdate /force`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to configure the administrative template registry values:

[Download Script: Configure-PawAtBiometricsAntiSpoofing.ps1](../implementation_scripts/Configure-PawAtBiometricsAntiSpoofing.ps1)

```powershell
#Configure-PawAtBiometricsAntiSpoofing.ps1
# Description: Configures Administrative Templates: Configure Biometrics Enhanced Anti-Spoofing for PAWs.

Write-Host "Configuring Administrative Templates: Configure Biometrics Enhanced Anti-Spoofing for PAWs..." -ForegroundColor Cyan

if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures" -Name "EnhancedAntiSpoofing" -Value 1 -Type DWord -Force

Write-Host "[+] Administrative Templates: Configure Biometrics Enhanced Anti-Spoofing for PAWs applied successfully." -ForegroundColor Green
```

*To verify the configuration:*

[Download Script: Get-PawAtBiometricsAntiSpoofingStatus.ps1](../audit_scripts/Get-PawAtBiometricsAntiSpoofingStatus.ps1)

```powershell
#Get-PawAtBiometricsAntiSpoofingStatus.ps1
# Description: Audits Administrative Templates: Configure Biometrics Enhanced Anti-Spoofing for PAWs.

Write-Host "--- Auditing Administrative Templates: Configure Biometrics Enhanced Anti-Spoofing for PAWs ---" -ForegroundColor Cyan
$script:Vulnerable = $false

$TargetKey = "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures"
$ValueName = "EnhancedAntiSpoofing"
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

if ($script:Vulnerable) {
    Write-Host "Audit Result: VULNERABLE" -ForegroundColor Red
    exit 1
} else {
    Write-Host "Audit Result: SECURE" -ForegroundColor Green
    exit 0
}
```

---

## Sources & Compliance References
* **CIS Benchmark**: CIS Microsoft Windows 10 Enterprise Benchmark: Section 18.10.11.1; CIS Microsoft Windows 11 Enterprise Benchmark: Section 18.10.11.1
* **DISA STIG**: Windows 10 STIG Rule WN10-CC-000315, Windows 11 STIG Rule WN11-CC-000315
* **ANSSI Active Directory Hardening Guide**: Section 3.1 (Biometric authentication security requirements)
* **Microsoft Privileged Access Workstation Guidance**: PAW Biometric and Strong Authentication Baseline
