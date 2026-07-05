# [REQ-DC-097] Configure Behavioral Network Remote Encryption Protection Aggressiveness on Domain Controllers

## Target Scope
* **Applicable Systems**: Domain Controllers.
* **Operating Systems**: Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Administrative Templates\Windows Components\Windows Defender Antivirus\Remediation\Behavioral Network Blocks`
  * **Registry Location**:
    * `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Remediation\Behavioral Network Blocks\Remote Encryption Protection`
      * `RemoteEncryptionProtectionAggressiveness` = `1` (REG_DWORD)

---

## Rationale
Ransomware groups target SYSVOL and SYSVOL shares on Domain Controllers to deploy encrypted templates or payloads. Enabling remote encryption protection aggressiveness blocks remote network-driven encryption attempts immediately.

---

## Legacy Impact & Compatibility
None. Blocks behavioral patterns matching ransomware network encryption engines.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Navigate to: Computer Configuration\Administrative Templates\Windows Components\Windows Defender Antivirus\Remediation\Behavioral Network Blocks
2. Set 'Configure behavioral network remote encryption protection aggressiveness' to 'Enabled' (Select '1')

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-DefenderRemoteEncryptionProtection.ps1](../implementation_scripts/Configure-DefenderRemoteEncryptionProtection.ps1)

```powershell
# Configure-DefenderRemoteEncryptionProtection.ps1
$Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Remediation\Behavioral Network Blocks\Remote Encryption Protection"
if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
Set-ItemProperty -Path $Path -Name "RemoteEncryptionProtectionAggressiveness" -Value 1 -Type DWord -Force
```

*To audit the hardening status:*
[Download Script: Get-DefenderRemoteEncryptionProtectionStatus.ps1](../audit_scripts/Get-DefenderRemoteEncryptionProtectionStatus.ps1)

```powershell
# Get-DefenderRemoteEncryptionProtectionStatus.ps1
$Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Remediation\Behavioral Network Blocks\Remote Encryption Protection"
$Reg = Get-ItemProperty -Path $Path -Name "RemoteEncryptionProtectionAggressiveness" -ErrorAction SilentlyContinue
if ($Reg -and $Reg.RemoteEncryptionProtectionAggressiveness -eq 1) {
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
