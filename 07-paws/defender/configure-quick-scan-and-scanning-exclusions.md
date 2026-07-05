# [REQ-PAW-067] Configure Quick Scan and Scanning Exclusions for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration.
* **Operating Systems**: Windows 10 Enterprise (1607+) and Windows 11 Enterprise.

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Administrative Templates\Windows Components\Windows Defender Antivirus\Scan`
  * **Registry Location**:
    * `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan`
      * `QuickScanIncludeExclusions` = `1` (REG_DWORD)
    * `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan`
      * `DisablePackedExeScanning` = `0` (REG_DWORD)

---

## Rationale
Malware frequently tries to establish persistence in excluded directories or inside packed/compressed executables. Forcing quick scans to include excluded files and ensuring packed file structures are recursively scanned prevents malware evasion.

---

## Legacy Impact & Compatibility
Increased quick scan times depending on folder sizes and compression ratios.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Navigate to: Computer Configuration\Administrative Templates\Windows Components\Windows Defender Antivirus\Scan
2. Set 'Scan excluded files and directories during quick scans' to 'Enabled'
3. Set 'Turn off scanning of packed executables' to 'Disabled'

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-PawDefenderQuickScan.ps1](../implementation_scripts/Configure-PawDefenderQuickScan.ps1)

```powershell
# Configure-PawDefenderQuickScan.ps1
Set-MpPreference -DisablePackedExeScanning $false
$ScanPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan"
if (-not (Test-Path $ScanPath)) { New-Item -Path $ScanPath -Force | Out-Null }
Set-ItemProperty -Path $ScanPath -Name "QuickScanIncludeExclusions" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $ScanPath -Name "DisablePackedExeScanning" -Value 0 -Type DWord -Force
```

*To audit the hardening status:*
[Download Script: Get-PawDefenderQuickScanStatus.ps1](../audit_scripts/Get-PawDefenderQuickScanStatus.ps1)

```powershell
# Get-PawDefenderQuickScanStatus.ps1
$Pref = Get-MpPreference
$Reg = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" -Name "QuickScanIncludeExclusions" -ErrorAction SilentlyContinue
$RegPack = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" -Name "DisablePackedExeScanning" -ErrorAction SilentlyContinue
if (($Pref.DisablePackedExeScanning -eq $false -or ($RegPack -and $RegPack.DisablePackedExeScanning -eq 0)) -and
    ($Reg -and $Reg.QuickScanIncludeExclusions -eq 1)) {
    Write-Output "Compliant"
    exit 0
} else {
    Write-Output "Non-Compliant"
    exit 1
}
```

---

## Sources & Compliance References
* **CIS Microsoft Windows 10 Benchmark**: Section 18.9 (Windows Defender Antivirus configuration parameters)
* **ANSSI Active Directory Hardening Guide**: Protective controls baselines on Privileged Access Workstations
