# [REQ-PAW-075] Configure AMSI Authenticode Signature Verification for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration.
* **Operating Systems**: Windows 10 Enterprise (1607+) and Windows 11 Enterprise.

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Preferences\Windows Settings\Registry`
  * **Registry Location**:
    * `HKLM\SOFTWARE\Microsoft\AMSI`
      * `FeatureBits` = `2` (REG_DWORD)

---

## Rationale
Enforcing signature checks on registered Antimalware Scan Interface (AMSI) providers blocks attackers from registering unsigned rogue AMSI provider DLLs to bypass script analysis.

---

## Legacy Impact & Compatibility
Third-party antivirus/security providers must register using signed Authenticode binaries to prevent being blocked.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Navigate to: Computer Configuration\Preferences\Windows Settings\Registry
2. Right-click and select New -> Registry Item
3. Configure Action: Update, Hive: HKEY_LOCAL_MACHINE, Key Path: SOFTWARE\Microsoft\AMSI, Value Name: FeatureBits, Value Type: REG_DWORD, Value Data: 2

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-PawDefenderAmsiSignature.ps1](../implementation_scripts/Configure-PawDefenderAmsiSignature.ps1)

```powershell
# Configure-PawDefenderAmsiSignature.ps1
$AmsiPath = "HKLM:\SOFTWARE\Microsoft\AMSI"
if (-not (Test-Path $AmsiPath)) { New-Item -Path $AmsiPath -Force | Out-Null }
Set-ItemProperty -Path $AmsiPath -Name "FeatureBits" -Value 2 -Type DWord -Force
```

*To audit the hardening status:*
[Download Script: Get-PawDefenderAmsiSignatureStatus.ps1](../audit_scripts/Get-PawDefenderAmsiSignatureStatus.ps1)

```powershell
# Get-PawDefenderAmsiSignatureStatus.ps1
$AmsiPath = "HKLM:\SOFTWARE\Microsoft\AMSI"
if (Test-Path $AmsiPath) {
    $AmsiBits = Get-ItemProperty -Path $AmsiPath -Name "FeatureBits" -ErrorAction SilentlyContinue
    if ($AmsiBits -and $AmsiBits.FeatureBits -eq 2) {
        Write-Output "Compliant"
        exit 0
    }
}
Write-Output "Non-Compliant"
exit 1
```

---

## Sources & Compliance References
* **CIS Microsoft Windows 10 Benchmark**: Section 18.9 (Windows Defender Antivirus configuration parameters)
* **ANSSI Active Directory Hardening Guide**: Protective controls baselines on Privileged Access Workstations
