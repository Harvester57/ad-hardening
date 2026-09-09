# [REQ-END-194] Administrative Templates: Configure Biometrics Enhanced Anti-Spoofing

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers. *(For Tier 0 Privileged Access Workstations, refer to tightened baseline [REQ-PAW-183](../../07-paws/admin-templates/configure-paw-at-biometrics-anti-spoofing.md)).*
* **Operating Systems**: Windows 10 Enterprise/Professional (all supported builds), Windows 11 Enterprise/Pro.

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
Windows Hello facial recognition provides convenient, passwordless authentication using biometric verification. However, basic facial recognition systems that analyze only two-dimensional visible spectrum images are vulnerable to presentation attacks and physical spoofing.

### 1. Presentation Attacks and Biometric Spoofing Threats
Without enhanced anti-spoofing, standard facial recognition algorithms can be deceived by adversaries presenting artificial facial artifacts:
* **High-Resolution Photographs and Printouts**: Attackers can hold high-quality printed color photographs of an authorized user in front of the camera to unlock unattended workstations.
* **Digital Video and Mobile Screen Playback**: Adversaries can replay video clips or animated facial recordings from smartphones or tablets positioned directly before the webcam.
* **3D Masks and Synthetic Replays**: Advanced threat actors utilize silicone masks or synthetic deepfake video feeds to match biometric templates.

### 2. Mandatory Hardware Liveness and Infrared Depth Verification
Setting `EnhancedAntiSpoofing = 1` (by configuring the GPO "Configure enhanced anti-spoofing" to **Enabled**) mandates strict algorithmic and hardware liveness checks:
* The Windows Biometric Framework (WBF) enforces the use of dedicated near-infrared (near-IR) imaging sensors and structured light or time-of-flight (ToF) depth mapping.
* The biometric algorithm measures passive and active infrared reflection characteristics, which differ dramatically between living human skin, photographic paper, and backlit LCD/OLED screens.
* 3D facial geometry is analyzed to confirm volumetric depth, completely rejecting flat 2D photographs or video screens.
* Any camera hardware that does not meet Microsoft's certified Enhanced Anti-Spoofing security specifications is prevented from providing facial logon capabilities.

### 3. MITRE ATT&CK Mapping
* **T1110 - Brute Force / Biometric Spoofing**: Presentation attacks utilizing photographs or digital screens to bypass interactive workstation locks.
* **T1078 - Valid Accounts**: Unauthorized physical logon to enterprise endpoints using forged biometric credentials.

---

## Legacy Impact & Compatibility
* **Enterprise Hardware Requirements**: Workstations equipped with Windows Hello certified IR sensors (standard on modern enterprise business laptops including Lenovo ThinkPad, Dell Latitude, HP EliteBook, and Microsoft Surface devices) operate seamlessly with heightened anti-spoofing defenses.
* **Incompatible Hardware Behavior**: Endpoints equipped only with standard RGB webcams will disable facial recognition options in Windows Settings. Users on such devices must authenticate using enterprise smart cards, FIDO2 security keys, or passwords.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to workstations and member servers (e.g., `GPO_Hardening_Endpoints`).
3. Configure the following policies:

* Navigate to: `Computer Configuration\Policies\Administrative Templates\Windows Components\Biometrics\Facial Features`
  * **Configure enhanced anti-spoofing**: Set to `Enabled`

4. Link the GPO to the appropriate Organizational Unit and verify policy enforcement using `gpupdate /force`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to configure the administrative template registry values:

[Download Script: Configure-EndAtBiometricsAntiSpoofing.ps1](../implementation_scripts/Configure-EndAtBiometricsAntiSpoofing.ps1)

```powershell
#Configure-EndAtBiometricsAntiSpoofing.ps1
# Description: Configures Administrative Templates: Configure Biometrics Enhanced Anti-Spoofing.

Write-Host "Configuring Administrative Templates: Configure Biometrics Enhanced Anti-Spoofing..." -ForegroundColor Cyan

if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures" -Name "EnhancedAntiSpoofing" -Value 1 -Type DWord -Force

Write-Host "[+] Administrative Templates: Configure Biometrics Enhanced Anti-Spoofing applied successfully." -ForegroundColor Green
```

*To verify the configuration:*

[Download Script: Get-EndAtBiometricsAntiSpoofingStatus.ps1](../audit_scripts/Get-EndAtBiometricsAntiSpoofingStatus.ps1)

```powershell
#Get-EndAtBiometricsAntiSpoofingStatus.ps1
# Description: Audits Administrative Templates: Configure Biometrics Enhanced Anti-Spoofing.

Write-Host "--- Auditing Administrative Templates: Configure Biometrics Enhanced Anti-Spoofing ---" -ForegroundColor Cyan
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
* **Microsoft Security Guidance**: Windows Hello Enhanced Anti-Spoofing Architecture and Requirements
