# [REQ-PAW-149] User Profile: Preservation of Attachment Zone Information for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs)
* **Operating Systems**: Windows 10/11 Enterprise

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **Registry Settings**:
  * Registry: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments\SaveZoneInformation` = `2` (DWord)


---

## Rationale
Ensures the Attachment Manager preserves the Zone.Identifier alternate data stream (ADS) marking files downloaded from untrusted web zones, enforcing SmartScreen check prompts.

---

## Legacy Impact & Compatibility
* **Operational Impact**: Restricts legacy application hooks or diagnostic modes. Ensure testing in a representative staging environment prior to wide deployment.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Navigate to: `User Configuration \ Administrative Templates \ Windows Components \ Attachment Manager`
2. Configure the policy:
   * **Policy**: `Do not preserve zone information in file attachments` -> Set to **Disabled** (which configures `SaveZoneInformation` = `2` to preserve zone information)


---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-PawAuditAttachmentzone.ps1](../implementation_scripts/Configure-PawAuditAttachmentzone.ps1)

```powershell
# Configure-PawAuditAttachmentzone.ps1
Write-Host "Enforcing System Mitigation control: attachment-zone..." -ForegroundColor Cyan

# Set Registry value: SaveZoneInformation
if (-not (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments")) { New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Force | Out-Null }
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "SaveZoneInformation" -Value 2 -Type DWord -Force
Write-Host "    Enforced SaveZoneInformation = 2" -ForegroundColor Green


```

*To audit the hardening status:*
[Download Script: Get-PawAuditAttachmentzoneStatus.ps1](../audit_scripts/Get-PawAuditAttachmentzoneStatus.ps1)

```powershell
# Get-PawAuditAttachmentzoneStatus.ps1
$script:Vulnerable = $false

# Audit Registry value: SaveZoneInformation
$RegVal = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "SaveZoneInformation" -ErrorAction SilentlyContinue
if (-not $RegVal -or $RegVal.SaveZoneInformation -ne 2) {
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
