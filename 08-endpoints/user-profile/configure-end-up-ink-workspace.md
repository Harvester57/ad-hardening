# [REQ-END-162] User Profile: Restrict Windows Ink Workspace on Lock Screen for Endpoints

## Target Scope
* **Applicable Systems**: Tier 2 Client Workstations
* **Operating Systems**: Windows 10/11 Enterprise/Professional

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **Registry Settings**:
  * Registry: `HKLM\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace\AllowWindowsInkWorkspace` = `1` (DWord)


---

## Rationale
Disabling access to the Windows Ink Workspace on the lock screen prevents unauthorized physical users from invoking drawing tools, scripts, or apps without authenticating.

---

## Legacy Impact & Compatibility
* **Operational Impact**: Restricts legacy application hooks or diagnostic modes. Ensure testing in a representative staging environment prior to wide deployment.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Navigate to: `Computer Configuration \ Administrative Templates \ Windows Components \ Windows Ink Workspace`
2. Configure the policy:
   * **Policy**: `Allow Windows Ink Workspace` -> Set to **Enabled**
   * **Action**: Choose **On, but disallow access above lock** (which configures `AllowWindowsInkWorkspace` = `1`)


---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-EndAuditInkworkspace.ps1](../implementation_scripts/Configure-EndAuditInkworkspace.ps1)

```powershell
# Configure-EndAuditInkworkspace.ps1
Write-Host "Enforcing System Mitigation control: ink-workspace..." -ForegroundColor Cyan

# Set Registry value: AllowWindowsInkWorkspace
if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace")) { New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" -Force | Out-Null }
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" -Name "AllowWindowsInkWorkspace" -Value 1 -Type DWord -Force
Write-Host "    Enforced AllowWindowsInkWorkspace = 1" -ForegroundColor Green


```

*To audit the hardening status:*
[Download Script: Get-EndAuditInkworkspaceStatus.ps1](../audit_scripts/Get-EndAuditInkworkspaceStatus.ps1)

```powershell
# Get-EndAuditInkworkspaceStatus.ps1
$script:Vulnerable = $false

# Audit Registry value: AllowWindowsInkWorkspace
$RegVal = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" -Name "AllowWindowsInkWorkspace" -ErrorAction SilentlyContinue
if (-not $RegVal -or $RegVal.AllowWindowsInkWorkspace -ne 1) {
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
