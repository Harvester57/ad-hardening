# [REQ-DC-092] Configure Tamper Protection on Domain Controllers

## Target Scope
* **Applicable Systems**: Domain Controllers.
* **Operating Systems**: Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Administrative Templates\Windows Components\Windows Security\Tamper Protection`
  * **Registry Location**:
    * `HKLM\SOFTWARE\Microsoft\Windows Defender\Features`
      * `TamperProtection` = `5` (REG_DWORD)

---

## Rationale
Tamper Protection prevents local administrators or compromised system accounts from disabling Windows Defender services, real-time scanning, or modifying active exclusions locally. This blocks a primary malware persistence vector.

---

## Legacy Impact & Compatibility
Local registry modifications to Defender configurations will be ignored. All changes must originate from central templates or cloud console panels.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Navigate to: Computer Configuration\Administrative Templates\Windows Components\Windows Security\Tamper Protection
2. Set 'Protect Windows Security settings from tampering' to 'Enabled' (Block or On depending on ADMX version)

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-DefenderTamperProtection.ps1](../implementation_scripts/Configure-DefenderTamperProtection.ps1)

```powershell
# Configure-DefenderTamperProtection.ps1
$FeaturesPath = "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features"
if (-not (Test-Path $FeaturesPath)) { New-Item -Path $FeaturesPath -Force | Out-Null }
try {
    Set-ItemProperty -Path $FeaturesPath -Name "TamperProtection" -Value 5 -Type DWord -ErrorAction Stop -Force
} catch {
    Write-Warning "Registry blocked. Tamper Protection registry key is normally protected by TrustedInstaller. Ensure GPO setting is applied."
}
```

*To audit the hardening status:*
[Download Script: Get-DefenderTamperProtectionStatus.ps1](../audit_scripts/Get-DefenderTamperProtectionStatus.ps1)

```powershell
# Get-DefenderTamperProtectionStatus.ps1
$FeaturesPath = "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features"
$TamperVal = Get-ItemProperty -Path $FeaturesPath -Name "TamperProtection" -ErrorAction SilentlyContinue
if ($TamperVal -and $TamperVal.TamperProtection -eq 5) {
    Write-Output "Compliant"
    exit 0
} else {
    Write-Output "Non-Compliant"
    exit 1
}
```

---

## Sources & Compliance References
* **CIS Microsoft Windows Server Benchmark**: Section 18.9 (Windows Defender Antivirus configuration parameters)
* **ANSSI Active Directory Hardening Guide**: Protective controls baselines on Domain Controllers
