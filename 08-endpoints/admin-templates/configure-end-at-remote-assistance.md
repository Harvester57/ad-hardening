# [REQ-END-190] Administrative Templates: Disable Remote Assistance

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers.
* **Operating Systems**: Windows 10 (and above) Enterprise/Professional, Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**:
  * `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fAllowUnsolicited` = `0`

---

## Rationale
Unsolicited Remote Assistance permits an administrator or support technician to initiate remote session connections to client endpoints without an explicit user invitation. If compromised, this capability allows adversaries with elevated domain privileges to silently observe or control interactive user desktop sessions.

---

## Legacy Impact & Compatibility
* **Operational Impact**: Helpdesk staff cannot offer unsolicited remote assistance. User-initiated assistance or approved enterprise remote support solutions (with session auditing) must be utilized.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to workstations and member servers (e.g., `GPO_Hardening_Endpoints`).
3. Configure the following policies:

* Navigate to: `Computer Configuration\Policies\Administrative Templates\System\Remote Assistance`
  * **Configure Offer Remote Assistance**: Set to `Disabled`

4. Link the GPO to the appropriate Organizational Unit and verify replication.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to configure the administrative template registry values:

[Download Script: Configure-EndAtRemoteAssistance.ps1](../implementation_scripts/Configure-EndAtRemoteAssistance.ps1)

```powershell
#Configure-EndAtRemoteAssistance.ps1
# Description: Configures Administrative Templates: Disable Remote Assistance.

Write-Host "Configuring Administrative Templates: Disable Remote Assistance..." -ForegroundColor Cyan

if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fAllowUnsolicited" -Value 0 -Type DWord -Force

Write-Host "[+] Administrative Templates: Disable Remote Assistance applied successfully." -ForegroundColor Green
```

*To verify the configuration:*

[Download Script: Get-EndAtRemoteAssistanceStatus.ps1](../audit_scripts/Get-EndAtRemoteAssistanceStatus.ps1)

```powershell
#Get-EndAtRemoteAssistanceStatus.ps1
# Description: Audits Administrative Templates: Disable Remote Assistance.

Write-Host "--- Auditing Administrative Templates: Disable Remote Assistance ---" -ForegroundColor Cyan
$script:Vulnerable = $false

$TargetKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
$ValueName = "fAllowUnsolicited"
$ExpectedValue = 0
if (Test-Path -Path $TargetKey) {
    $Prop = Get-ItemProperty -Path $TargetKey -Name $ValueName -ErrorAction SilentlyContinue
    if ($null -ne $Prop) {
        $Actual = $Prop.$ValueName
        if ($Actual -eq $ExpectedValue) {
            Write-Host "  [+] $ValueName = $($Actual) (Secure)" -ForegroundColor Green
        } else {
            Write-Host "  [!] MISMATCH: $ValueName = $($Actual) (Expected: $($ExpectedValue))" -ForegroundColor Red
            $script:Vulnerable = $true
        }
    } else {
        Write-Host "  [!] MISSING VALUE: $ValueName (Expected: $($ExpectedValue))" -ForegroundColor Red
        $script:Vulnerable = $true
    }
} else {
    Write-Host "  [!] MISSING KEY: $TargetKey" -ForegroundColor Red
    $script:Vulnerable = $true
}

if ($script:Vulnerable) {
    Write-Host "Audit Result: VULNERABLE" -ForegroundColor Red
    exit 1
} else {
    Write-Host "Audit Result: SECURE" -ForegroundColor Green
    exit 0
}
```

---

## Sources & Compliance References
* **CIS Benchmark**: CIS Microsoft Windows Client Benchmark: Section 18.9.35.1
* **ANSSI Active Directory Hardening Guide**: Baseline security parameters for managed Windows environments
* **Microsoft Security Baseline**: Recommended administrative template and component restrictions
