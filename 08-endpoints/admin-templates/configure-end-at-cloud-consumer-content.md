# [REQ-END-195] Administrative Templates: Disable Cloud Consumer Account State Content

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers.
* **Operating Systems**: Windows 10 (and above) Enterprise/Professional, Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: Low
* **GPO Path / Registry Location**:
  * `HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent\DisableConsumerAccountStateContent` = `1`

---

## Rationale
Windows features consumer account state content cards and promotional recommendations in system menus. Disabling this content stops background queries to consumer cloud services, eliminates targeted promotional telemetry, and maintains a clean enterprise desktop interface.

---

## Legacy Impact & Compatibility
* **Operational Impact**: Consumer account recommendation banners will be removed from system menus.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to workstations and member servers (e.g., `GPO_Hardening_Endpoints`).
3. Configure the following policies:

* Navigate to: `Computer Configuration\Policies\Administrative Templates\Windows Components\Cloud Content`
  * **Turn off cloud consumer account state content**: Set to `Enabled`

4. Link the GPO to the appropriate Organizational Unit and verify replication.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to configure the administrative template registry values:

[Download Script: Configure-EndAtCloudConsumerContent.ps1](../implementation_scripts/Configure-EndAtCloudConsumerContent.ps1)

```powershell
#Configure-EndAtCloudConsumerContent.ps1
# Description: Configures Administrative Templates: Disable Cloud Consumer Account State Content.

Write-Host "Configuring Administrative Templates: Disable Cloud Consumer Account State Content..." -ForegroundColor Cyan

if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableConsumerAccountStateContent" -Value 1 -Type DWord -Force

Write-Host "[+] Administrative Templates: Disable Cloud Consumer Account State Content applied successfully." -ForegroundColor Green
```

*To verify the configuration:*

[Download Script: Get-EndAtCloudConsumerContentStatus.ps1](../audit_scripts/Get-EndAtCloudConsumerContentStatus.ps1)

```powershell
#Get-EndAtCloudConsumerContentStatus.ps1
# Description: Audits Administrative Templates: Disable Cloud Consumer Account State Content.

Write-Host "--- Auditing Administrative Templates: Disable Cloud Consumer Account State Content ---" -ForegroundColor Cyan
$script:Vulnerable = $false

$TargetKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
$ValueName = "DisableConsumerAccountStateContent"
$ExpectedValue = 1
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
* **CIS Benchmark**: CIS Microsoft Windows Client Benchmark: Section 18.10.13.1
* **ANSSI Active Directory Hardening Guide**: Baseline security parameters for managed Windows environments
* **Microsoft Security Baseline**: Recommended administrative template and component restrictions
