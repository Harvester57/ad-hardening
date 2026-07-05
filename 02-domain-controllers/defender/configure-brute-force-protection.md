# [REQ-DC-096] Configure Behavioral Network Brute Force Protection Aggressiveness on Domain Controllers

## Target Scope
* **Applicable Systems**: Domain Controllers.
* **Operating Systems**: Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Administrative Templates\Windows Components\Windows Defender Antivirus\Remediation\Behavioral Network Blocks`
  * **Registry Location**:
    * `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Remediation\Behavioral Network Blocks\Brute Force Protection`
      * `BruteForceProtectionAggressiveness` = `1` (REG_DWORD)

---

## Rationale
Active Directory Domain Controllers are prime targets for automated password brute-forcing and Kerberos pre-authentication spraying attacks. Setting brute force protection aggressiveness to 1 enables immediate behavioral blocks against network authentication flood sources.

---

## Legacy Impact & Compatibility
May occasionally trigger blocks on legitimate tools performing aggressive directory scans or rapid administrative sync scripts if not scoped correctly.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Navigate to: Computer Configuration\Administrative Templates\Windows Components\Windows Defender Antivirus\Remediation\Behavioral Network Blocks
2. Set 'Configure behavioral network brute force protection aggressiveness' to 'Enabled' (Select '1')

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-DefenderBruteForceProtection.ps1](../implementation_scripts/Configure-DefenderBruteForceProtection.ps1)

```powershell
# Configure-DefenderBruteForceProtection.ps1
$Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Remediation\Behavioral Network Blocks\Brute Force Protection"
if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
Set-ItemProperty -Path $Path -Name "BruteForceProtectionAggressiveness" -Value 1 -Type DWord -Force
```

*To audit the hardening status:*
[Download Script: Get-DefenderBruteForceProtectionStatus.ps1](../audit_scripts/Get-DefenderBruteForceProtectionStatus.ps1)

```powershell
# Get-DefenderBruteForceProtectionStatus.ps1
$Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Remediation\Behavioral Network Blocks\Brute Force Protection"
$Reg = Get-ItemProperty -Path $Path -Name "BruteForceProtectionAggressiveness" -ErrorAction SilentlyContinue
if ($Reg -and $Reg.BruteForceProtectionAggressiveness -eq 1) {
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
