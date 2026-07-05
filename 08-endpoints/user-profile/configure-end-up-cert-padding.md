# [REQ-END-155] User Profile: Authenticode Signature Certificate Padding Check for Endpoints

## Target Scope
* **Applicable Systems**: Tier 2 Client Workstations
* **Operating Systems**: Windows 10/11 Enterprise/Professional

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **Registry Settings**:
  * Registry: `HKLM\Software\Microsoft\Cryptography\Wintrust\Config\EnableCertPaddingCheck` = `1` (DWord)
  * Registry: `HKLM\Software\Wow6432Node\Microsoft\Cryptography\Wintrust\Config\EnableCertPaddingCheck` = `1` (DWord)


---

## Rationale
Blocks padding execution attacks on Authenticode signed binaries by validating that there is no extra unverified payload appended to the certificate signature block.

---

## Legacy Impact & Compatibility
* **Operational Impact**: Restricts legacy application hooks or diagnostic modes. Ensure testing in a representative staging environment prior to wide deployment.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Deploy the following Registry settings using Group Policy Preferences (Registry Extension):
  * Registry: `HKLM\Software\Microsoft\Cryptography\Wintrust\Config\EnableCertPaddingCheck` = `1` (DWord)
  * Registry: `HKLM\Software\Wow6432Node\Microsoft\Cryptography\Wintrust\Config\EnableCertPaddingCheck` = `1` (DWord)


---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-EndAuditCertpadding.ps1](../implementation_scripts/Configure-EndAuditCertpadding.ps1)

```powershell
# Configure-EndAuditCertpadding.ps1
Write-Host "Enforcing System Mitigation control: cert-padding..." -ForegroundColor Cyan

# Set Registry value: EnableCertPaddingCheck
if (-not (Test-Path "HKLM:\Software\Microsoft\Cryptography\Wintrust\Config")) { New-Item -Path "HKLM:\Software\Microsoft\Cryptography\Wintrust\Config" -Force | Out-Null }
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Cryptography\Wintrust\Config" -Name "EnableCertPaddingCheck" -Value 1 -Type DWord -Force
Write-Host "    Enforced EnableCertPaddingCheck = 1" -ForegroundColor Green

# Set Registry value: EnableCertPaddingCheck
if (-not (Test-Path "HKLM:\Software\Wow6432Node\Microsoft\Cryptography\Wintrust\Config")) { New-Item -Path "HKLM:\Software\Wow6432Node\Microsoft\Cryptography\Wintrust\Config" -Force | Out-Null }
Set-ItemProperty -Path "HKLM:\Software\Wow6432Node\Microsoft\Cryptography\Wintrust\Config" -Name "EnableCertPaddingCheck" -Value 1 -Type DWord -Force
Write-Host "    Enforced EnableCertPaddingCheck = 1" -ForegroundColor Green


```

*To audit the hardening status:*
[Download Script: Get-EndAuditCertpaddingStatus.ps1](../audit_scripts/Get-EndAuditCertpaddingStatus.ps1)

```powershell
# Get-EndAuditCertpaddingStatus.ps1
$script:Vulnerable = $false

# Audit Registry value: EnableCertPaddingCheck
$RegVal = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Cryptography\Wintrust\Config" -Name "EnableCertPaddingCheck" -ErrorAction SilentlyContinue
if (-not $RegVal -or $RegVal.EnableCertPaddingCheck -ne 1) {
    $script:Vulnerable = $true
}

# Audit Registry value: EnableCertPaddingCheck
$RegVal = Get-ItemProperty -Path "HKLM:\Software\Wow6432Node\Microsoft\Cryptography\Wintrust\Config" -Name "EnableCertPaddingCheck" -ErrorAction SilentlyContinue
if (-not $RegVal -or $RegVal.EnableCertPaddingCheck -ne 1) {
    $script:Vulnerable = $true
}

if ($script:Vulnerable) {
    Write-Output "Non-Compliant"
    exit 1
} else {
    Write-Output "Compliant"
    exit 0
}
```

---

## Sources & Compliance References
* **ANSSI Active Directory Hardening Guide**: Client security baselines
* **CIS Windows 10/11 Client Benchmark**: Section 18.9 (Administrative Templates: System \ Mitigations) and Registry restrictions
