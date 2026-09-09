# [REQ-PAW-192] Configure Remote Encryption Protection Mode for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration.
* **Operating Systems**: Windows 10 Enterprise (1607+) and Windows 11 Enterprise.

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Defender Antivirus\Remediation\Behavioral Network Blocks\Brute Force Protection` -> **Configure Remote Encryption Protection Mode**
  * **Registry Location**:
    * `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Remediation\Behavioral Network Blocks\Brute Force Protection`
      * `BruteForceProtectionConfiguredState` = `2` (REG_DWORD)

---

## Rationale
Privileged Access Workstations (PAWs) must maintain the highest standard of endpoint protection against ransomware and lateral movement attempts. Remote Encryption Protection detects and terminates network ransomware attempting to encrypt files over SMB shares. Enforcing Block mode terminates the malicious remote process or network connection attempting rapid or unauthorized file encryption, safeguarding Tier 0 administrative assets from network-based extortion attacks.

---

## Legacy Impact & Compatibility
* **Operational Impact**: High-volume legitimate batch modifications to SMB shares could theoretically trigger heuristics. Because PAWs are strictly dedicated administrative workstations with no local business file shares, operational impact is negligible.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to PAWs Organizational Unit (e.g., `GPO_Hardening_PAW`).
3. Navigate to: `Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Defender Antivirus\Remediation\Behavioral Network Blocks\Brute Force Protection`
4. Double-click **Configure Remote Encryption Protection Mode**.
5. Set the policy to **Enabled**, and select **Block** (value `2`) in the dropdown options.
6. Link the GPO to the appropriate Organizational Unit and verify replication.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to configure the Remote Encryption Protection registry value on PAWs:

[Download Script: Configure-PawRemoteEncryptionProtection.ps1](../implementation_scripts/Configure-PawRemoteEncryptionProtection.ps1)

```powershell
# Configure-PawRemoteEncryptionProtection.ps1
# Description: Configures Microsoft Defender Remote Encryption Protection in Block mode on PAWs.

Write-Host "Configuring Microsoft Defender Remote Encryption Protection for PAWs..." -ForegroundColor Cyan

$KeyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Remediation\Behavioral Network Blocks\Brute Force Protection"
if (-not (Test-Path -Path $KeyPath)) {
    New-Item -Path $KeyPath -Force | Out-Null
}
Set-ItemProperty -Path $KeyPath -Name "BruteForceProtectionConfiguredState" -Value 2 -Type DWord -Force

Write-Host "[+] Remote Encryption Protection applied successfully on PAWs (Block mode)." -ForegroundColor Green
```

*To audit the hardening status:*

[Download Script: Get-PawRemoteEncryptionProtectionStatus.ps1](../audit_scripts/Get-PawRemoteEncryptionProtectionStatus.ps1)

```powershell
# Get-PawRemoteEncryptionProtectionStatus.ps1
# Description: Audits Microsoft Defender Remote Encryption Protection configuration status on PAWs.

$KeyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Remediation\Behavioral Network Blocks\Brute Force Protection"
$Reg = Get-ItemProperty -Path $KeyPath -Name "BruteForceProtectionConfiguredState" -ErrorAction SilentlyContinue

if ($Reg -and $Reg.BruteForceProtectionConfiguredState -eq 2) {
    Write-Output "Compliant"
    exit 0
} else {
    Write-Output "Non-Compliant"
    exit 1
}
```

---

## Sources & Compliance References
* **CIS Benchmark**: CIS Microsoft Windows Client Benchmark: Section 18.10.43.11.1.1.2
* **ANSSI Active Directory Hardening Guide**: Recommendations for Tier 0 Privileged Access Workstations (PAWs)
* **Microsoft Security Baseline**: Recommended administrative template and component restrictions
