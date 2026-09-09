# [REQ-END-203] Configure Remote Encryption Protection Mode

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers.
* **Operating Systems**: Windows 10 (and above) Enterprise/Professional, Windows Server 2016 (and above).

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
Remote Encryption Protection actively detects and terminates network ransomware attempting to encrypt files over SMB shares. Enforcing Block mode terminates the malicious remote process or connection attempting rapid or unauthorized file encryption over network shares, halting lateral encryption attacks from unmanaged or compromised domain assets.

---

## Legacy Impact & Compatibility
* **Operational Impact**: High-volume legitimate batch modifications to SMB shares by custom scripts could theoretically trip aggressive heuristics. Block mode severs the offending session. Pilot testing in Audit mode (`1`) is recommended for environments running legacy custom batch processing tools before transitioning to Block mode (`2`).

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to workstations and member servers (e.g., `GPO_Hardening_Endpoints`).
3. Navigate to: `Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Defender Antivirus\Remediation\Behavioral Network Blocks\Brute Force Protection`
4. Double-click **Configure Remote Encryption Protection Mode**.
5. Set the policy to **Enabled**, and select **Block** (value `2`) in the dropdown options.
6. Link the GPO to the appropriate Organizational Unit and verify replication.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to configure the Remote Encryption Protection registry value:

[Download Script: Configure-RemoteEncryptionProtection.ps1](../implementation_scripts/Configure-RemoteEncryptionProtection.ps1)

```powershell
# Configure-RemoteEncryptionProtection.ps1
# Description: Configures Microsoft Defender Remote Encryption Protection in Block mode.

Write-Host "Configuring Microsoft Defender Remote Encryption Protection..." -ForegroundColor Cyan

$KeyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Remediation\Behavioral Network Blocks\Brute Force Protection"
if (-not (Test-Path -Path $KeyPath)) {
    New-Item -Path $KeyPath -Force | Out-Null
}
Set-ItemProperty -Path $KeyPath -Name "BruteForceProtectionConfiguredState" -Value 2 -Type DWord -Force

Write-Host "[+] Remote Encryption Protection applied successfully (Block mode)." -ForegroundColor Green
```

*To audit the hardening status:*

[Download Script: Get-RemoteEncryptionProtectionStatus.ps1](../audit_scripts/Get-RemoteEncryptionProtectionStatus.ps1)

```powershell
# Get-RemoteEncryptionProtectionStatus.ps1
# Description: Audits Microsoft Defender Remote Encryption Protection configuration status.

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
* **ANSSI Active Directory Hardening Guide**: Baseline security parameters for managed Windows environments
* **Microsoft Security Baseline**: Recommended administrative template and component restrictions
