# [REQ-PAW-150] User Profile: Disable Windows Game DVR for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs)
* **Operating Systems**: Windows 10/11 Enterprise

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **Registry Settings**:
  * Registry: `HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR\AllowGameDVR` = `0` (DWord)


---

## Rationale
Disabling Game DVR blocks background media recording agents, conserving local computing cycles and preventing administrative session leakage via broadcast APIs.

---

## Legacy Impact & Compatibility
* **Operational Impact**: Restricts legacy application hooks or diagnostic modes. Ensure testing in a representative staging environment prior to wide deployment.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Navigate to: `Computer Configuration \ Administrative Templates \ Windows Components \ Windows Game Recording and Broadcasting`
2. Configure the policy:
   * **Policy**: `Enables or disables Windows Game Recording and Broadcasting` -> Set to **Disabled** (which configures `AllowGameDVR` = `0`)


---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-PawAuditGamedvr.ps1](../implementation_scripts/Configure-PawAuditGamedvr.ps1)

```powershell
# Configure-PawAuditGamedvr.ps1
Write-Host "Enforcing System Mitigation control: game-dvr..." -ForegroundColor Cyan

# Set Registry value: AllowGameDVR
if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR")) { New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Force | Out-Null }
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Value 0 -Type DWord -Force
Write-Host "    Enforced AllowGameDVR = 0" -ForegroundColor Green


```

*To audit the hardening status:*
[Download Script: Get-PawAuditGamedvrStatus.ps1](../audit_scripts/Get-PawAuditGamedvrStatus.ps1)

```powershell
# Get-PawAuditGamedvrStatus.ps1
$script:Vulnerable = $false

# Audit Registry value: AllowGameDVR
$RegVal = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -ErrorAction SilentlyContinue
if (-not $RegVal -or $RegVal.AllowGameDVR -ne 0) {
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
