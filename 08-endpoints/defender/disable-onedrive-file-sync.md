# [REQ-END-078] Disable OneDrive File Sync

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers.
* **Operating Systems**: Windows 10 (and above) Enterprise/Professional, Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Administrative Templates\Windows Components\OneDrive`
  * **Registry Location**:
    * `HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive`
      * `DisableFileSyncNGSC` = `1` (REG_DWORD)

---

## Rationale
Preventing OneDrive files from syncing automatically protects endpoints against automated synchronization of encrypted files during a ransomware event, and prevents unauthorized data exfiltration.

---

## Legacy Impact & Compatibility
OneDrive file synchronization will be completely disabled. Alternate storage paths must be used.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Navigate to: Computer Configuration\Administrative Templates\Windows Components\OneDrive
2. Set 'Prevent the usage of OneDrive for file storage' to 'Enabled'

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-DisableOneDriveSync.ps1](../implementation_scripts/Configure-DisableOneDriveSync.ps1)

```powershell
# Configure-DisableOneDriveSync.ps1
$Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive"
if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
Set-ItemProperty -Path $Path -Name "DisableFileSyncNGSC" -Value 1 -Type DWord -Force
```

*To audit the hardening status:*
[Download Script: Get-DisableOneDriveSyncStatus.ps1](../audit_scripts/Get-DisableOneDriveSyncStatus.ps1)

```powershell
# Get-DisableOneDriveSyncStatus.ps1
$Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive"
$Reg = Get-ItemProperty -Path $Path -Name "DisableFileSyncNGSC" -ErrorAction SilentlyContinue
if ($Reg -and $Reg.DisableFileSyncNGSC -eq 1) {
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
* **ANSSI Active Directory Hardening Guide**: Protective controls baselines on client workstations
