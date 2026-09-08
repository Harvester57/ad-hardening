# [REQ-END-205] Administrative Templates: Windows Store Updates and OS Upgrade Restrictions

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers.
* **Operating Systems**: Windows 10 (and above) Enterprise/Professional, Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**:
  * `HKLM\SOFTWARE\Policies\Microsoft\WindowsStore\AutoDownload` = `4`
  * `HKLM\SOFTWARE\Policies\Microsoft\WindowsStore\DisableOSUpgrade` = `1`

---

## Rationale
Permitting automatic Store app updates ensures packaged applications and system appx dependencies stay continuously patched against published vulnerabilities. Suppressing consumer Windows upgrade offers prevents unauthorized major OS feature version upgrades that circumvent IT change management and testing.

---

## Legacy Impact & Compatibility
* **Operational Impact**: Store apps receive automated updates; consumer version upgrade prompts are suppressed.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to workstations and member servers (e.g., `GPO_Hardening_Endpoints`).
3. Configure the following policies:

* Navigate to: `Computer Configuration\Policies\Administrative Templates\Windows Components\Store`
  * **Turn off Automatic Download and Install of updates**: Set to `Disabled` (Allow auto updates)
* Navigate to: `Computer Configuration\Policies\Administrative Templates\Windows Components\Store`
  * **Turn off the offer to update to the latest version of Windows**: Set to `Enabled`

4. Link the GPO to the appropriate Organizational Unit and verify replication.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to configure the administrative template registry values:

[Download Script: Configure-EndAtWindowsStoreRestrictions.ps1](../implementation_scripts/Configure-EndAtWindowsStoreRestrictions.ps1)

```powershell
#Configure-EndAtWindowsStoreRestrictions.ps1
# Description: Configures Administrative Templates: Windows Store Updates and OS Upgrade Restrictions.

Write-Host "Configuring Administrative Templates: Windows Store Updates and OS Upgrade Restrictions..." -ForegroundColor Cyan

if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Name "AutoDownload" -Value 4 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Name "DisableOSUpgrade" -Value 1 -Type DWord -Force

Write-Host "[+] Administrative Templates: Windows Store Updates and OS Upgrade Restrictions applied successfully." -ForegroundColor Green
```

*To verify the configuration:*

[Download Script: Get-EndAtWindowsStoreRestrictionsStatus.ps1](../audit_scripts/Get-EndAtWindowsStoreRestrictionsStatus.ps1)

```powershell
#Get-EndAtWindowsStoreRestrictionsStatus.ps1
# Description: Audits Administrative Templates: Windows Store Updates and OS Upgrade Restrictions.

Write-Host "--- Auditing Administrative Templates: Windows Store Updates and OS Upgrade Restrictions ---" -ForegroundColor Cyan
$script:Vulnerable = $false

$TargetKey = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore"
$ValueName = "AutoDownload"
$ExpectedValue = 4
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

$TargetKey = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore"
$ValueName = "DisableOSUpgrade"
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
* **CIS Benchmark**: CIS Microsoft Windows Client Benchmark: Section 18.10.66.2, Section 18.10.66.3
* **ANSSI Active Directory Hardening Guide**: Baseline security parameters for managed Windows environments
* **Microsoft Security Baseline**: Recommended administrative template and component restrictions
