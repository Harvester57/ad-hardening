# [REQ-PAW-148] User Profile: Disabling Injection of AppInit DLLs for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs)
* **Operating Systems**: Windows 10/11 Enterprise

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **Registry Settings**:
  * Registry: `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows\LoadAppInit_DLLs` = `0` (DWord)


---

## Rationale
AppInit DLL injection is a legacy mechanism that loads arbitrary user DLLs into every process that links user32.dll. Enforcing a complete ban (value 0) prevents unauthorized injection hooks.

---

## Legacy Impact & Compatibility
* **Operational Impact**: Restricts legacy application hooks or diagnostic modes. Ensure testing in a representative staging environment prior to wide deployment.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Deploy the following Registry settings using Group Policy Preferences (Registry Extension):
  * Registry: `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows\LoadAppInit_DLLs` = `0` (DWord)


---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-PawAuditAppinitdlls.ps1](../implementation_scripts/Configure-PawAuditAppinitdlls.ps1)

```powershell
# Configure-PawAuditAppinitdlls.ps1
Write-Host "Enforcing System Mitigation control: appinit-dlls..." -ForegroundColor Cyan

# Set Registry value: LoadAppInit_DLLs
if (-not (Test-Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows")) { New-Item -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows" -Force | Out-Null }
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows" -Name "LoadAppInit_DLLs" -Value 0 -Type DWord -Force
Write-Host "    Enforced LoadAppInit_DLLs = 0" -ForegroundColor Green


```

*To audit the hardening status:*
[Download Script: Get-PawAuditAppinitdllsStatus.ps1](../audit_scripts/Get-PawAuditAppinitdllsStatus.ps1)

```powershell
# Get-PawAuditAppinitdllsStatus.ps1
$script:Vulnerable = $false

# Audit Registry value: LoadAppInit_DLLs
$RegVal = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows" -Name "LoadAppInit_DLLs" -ErrorAction SilentlyContinue
if (-not $RegVal -or $RegVal.LoadAppInit_DLLs -ne 0) {
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
