# [REQ-PAW-183] Administrative Templates: Configure Biometrics Enhanced Anti-Spoofing for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration.
* **Operating Systems**: Windows 10 Enterprise (1607+) and Windows 11 Enterprise.

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**:
  * `HKLM\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures\EnhancedAntiSpoofing` = `1`

---

## Rationale
Standard facial recognition can potentially be spoofed using high-resolution photographs, video playback, or realistic masks. Enhanced anti-spoofing requires facial recognition algorithms to verify depth and infrared illumination data from compatible biometric hardware sensors before granting access.

---

## Legacy Impact & Compatibility
* **Operational Impact**: Devices with standard RGB-only webcams will not support facial recognition logon and must use smartcards or TPM-backed PINs.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to PAWs Organizational Unit (e.g., `GPO_Hardening_PAW`).
3. Configure the following policies:

* Navigate to: `Computer Configuration\Policies\Administrative Templates\Windows Components\Biometrics\Facial Features`
  * **Configure enhanced anti-spoofing**: Set to `Enabled`

4. Link the GPO to the appropriate Organizational Unit and verify replication.

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
* **CIS Benchmark**: CIS Microsoft Windows Client Benchmark: Section 18.10.9.1.1
* **ANSSI Active Directory Hardening Guide**: Baseline security parameters for managed Windows environments
* **Microsoft Security Baseline**: Recommended administrative template and component restrictions
