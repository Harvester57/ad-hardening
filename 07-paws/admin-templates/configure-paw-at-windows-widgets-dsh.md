# [REQ-PAW-195] Administrative Templates: Disable Windows Widgets and News Feed for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration.
* **Operating Systems**: Windows 10 Enterprise (1607+) and Windows 11 Enterprise.

---

## Implementation Details
* **Priority**: Low
* **GPO Path / Registry Location**:
  * `HKLM\SOFTWARE\Policies\Microsoft\Dsh\AllowNewsAndInterests` = `0`

---

## Rationale
Windows Widgets and News and Interests dynamically fetch unauthenticated internet news, weather, and third-party content onto the taskbar, generating continuous telemetry and background web requests. Disabling widgets eliminates this attack surface and eliminates unwanted distractions.

---

## Legacy Impact & Compatibility
* **Operational Impact**: The Widgets and News and Interests icon is removed from the taskbar.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to PAWs Organizational Unit (e.g., `GPO_Hardening_PAW`).
3. Configure the following policies:

* Navigate to: `Computer Configuration\Policies\Administrative Templates\Windows Components\Widgets`
  * **Allow widgets**: Set to `Disabled`

4. Link the GPO to the appropriate Organizational Unit and verify replication.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to configure the administrative template registry values:

[Download Script: Configure-PawAtWindowsWidgetsDsh.ps1](../implementation_scripts/Configure-PawAtWindowsWidgetsDsh.ps1)

```powershell
#Configure-PawAtWindowsWidgetsDsh.ps1
# Description: Configures Administrative Templates: Disable Windows Widgets and News Feed for PAWs.

Write-Host "Configuring Administrative Templates: Disable Windows Widgets and News Feed for PAWs..." -ForegroundColor Cyan

if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Dsh")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Dsh" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Dsh" -Name "AllowNewsAndInterests" -Value 0 -Type DWord -Force

Write-Host "[+] Administrative Templates: Disable Windows Widgets and News Feed for PAWs applied successfully." -ForegroundColor Green
```

*To verify the configuration:*

[Download Script: Get-PawAtWindowsWidgetsDshStatus.ps1](../audit_scripts/Get-PawAtWindowsWidgetsDshStatus.ps1)

```powershell
#Get-PawAtWindowsWidgetsDshStatus.ps1
# Description: Audits Administrative Templates: Disable Windows Widgets and News Feed for PAWs.

Write-Host "--- Auditing Administrative Templates: Disable Windows Widgets and News Feed for PAWs ---" -ForegroundColor Cyan
$script:Vulnerable = $false

$TargetKey = "HKLM:\SOFTWARE\Policies\Microsoft\Dsh"
$ValueName = "AllowNewsAndInterests"
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
* **CIS Benchmark**: CIS Microsoft Windows Client Benchmark: Section 18.10.72.1
* **ANSSI Active Directory Hardening Guide**: Baseline security parameters for managed Windows environments
* **Microsoft Security Baseline**: Recommended administrative template and component restrictions
