# [REQ-DC-075] Disable Real-Time Monitoring and Behavior Monitoring Override on Domain Controllers

## Target Scope
* **Applicable Systems**: Domain Controllers.
* **Operating Systems**: Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Administrative Templates\Windows Components\Windows Defender Antivirus\Real-time Protection`
  * **Registry Location**:
    * `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender`
      * `DisableAntiSpyware` = `0` (REG_DWORD)
    * `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection`
      * `DisableRealtimeMonitoring` = `0` (REG_DWORD)
    * `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection`
      * `DisableBehaviorMonitoring` = `0` (REG_DWORD)
    * `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection`
      * `DisableIOAVProtection` = `0` (REG_DWORD)
    * `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection`
      * `DisableScriptScanning` = `0` (REG_DWORD)

---

## Rationale
Real-time scanning, behavior monitoring, and script checking are the core dynamic defense mechanisms of Windows Defender. Disabling or bypassing these controls allows malicious scripts, file-based attacks, and unauthorized in-memory activities to execute undetected.

---

## Legacy Impact & Compatibility
Negligible operational impact. Real-time scanning introduces standard CPU overhead during file read/write operations.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Navigate to: Computer Configuration\Administrative Templates\Windows Components\Windows Defender Antivirus\Real-time Protection
2. Set 'Turn off real-time protection' to 'Disabled'
3. Set 'Turn on behavior monitoring' to 'Enabled'
4. Set 'Scan all downloaded files and attachments' to 'Enabled'
5. Set 'Turn on script scanning' to 'Enabled'

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-DefenderRtpDC.ps1](../implementation_scripts/Configure-DefenderRtpDC.ps1)

```powershell
# Configure-DefenderRtpDC.ps1
Set-MpPreference -DisableRealtimeMonitoring $false
Set-MpPreference -DisableBehaviorMonitoring $false
Set-MpPreference -DisableIOAVProtection $false
Set-MpPreference -DisableScriptScanning $false
$DefenderPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
if (-not (Test-Path $DefenderPath)) { New-Item -Path $DefenderPath -Force | Out-Null }
Set-ItemProperty -Path $DefenderPath -Name "DisableAntiSpyware" -Value 0 -Type DWord -Force
```

*To audit the hardening status:*
[Download Script: Get-DefenderRtpDCStatus.ps1](../audit_scripts/Get-DefenderRtpDCStatus.ps1)

```powershell
# Get-DefenderRtpDCStatus.ps1
$Pref = Get-MpPreference
$Reg = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -ErrorAction SilentlyContinue
if ($Pref.DisableRealtimeMonitoring -eq $false -and $Pref.DisableBehaviorMonitoring -eq $false -and $Pref.DisableIOAVProtection -eq $false -and $Pref.DisableScriptScanning -eq $false -and ($Reg -and $Reg.DisableAntiSpyware -eq 0)) {
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
