# [REQ-PAW-196] Administrative Templates: Disable Windows Automatic Restart Sign-On (ARSO) for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration.
* **Operating Systems**: Windows 10 Enterprise (1607+) and Windows 11 Enterprise.

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\DisableAutomaticRestartSignOn` = `1`

---

## Rationale
Automatic Restart Sign-On (ARSO) caches user credentials in memory to automatically log in and lock the desktop after Windows Update reboots. This credential staging mechanism creates exposure to physical memory extraction and DMA attacks. Disabling ARSO prevents credentials from persisting across automated reboots.

---

## Legacy Impact & Compatibility
* **Operational Impact**: Following a restart, the computer remains at the initial Windows login screen until the user manually authenticates.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to PAWs Organizational Unit (e.g., `GPO_Hardening_PAW`).
3. Configure the following policies:

* Navigate to: `Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Logon Options`
  * **Sign-in and lock last interactive user automatically after a restart**: Set to `Disabled`

4. Link the GPO to the appropriate Organizational Unit and verify replication.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to configure the administrative template registry values:

[Download Script: Configure-PawAtAutomaticRestartSignon.ps1](../implementation_scripts/Configure-PawAtAutomaticRestartSignon.ps1)

```powershell
#Configure-PawAtAutomaticRestartSignon.ps1
# Description: Configures Administrative Templates: Disable Windows Automatic Restart Sign-On (ARSO) for PAWs.

Write-Host "Configuring Administrative Templates: Disable Windows Automatic Restart Sign-On (ARSO) for PAWs..." -ForegroundColor Cyan

if (-not (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System")) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableAutomaticRestartSignOn" -Value 1 -Type DWord -Force

Write-Host "[+] Administrative Templates: Disable Windows Automatic Restart Sign-On (ARSO) for PAWs applied successfully." -ForegroundColor Green
```

*To verify the configuration:*

[Download Script: Get-PawAtAutomaticRestartSignonStatus.ps1](../audit_scripts/Get-PawAtAutomaticRestartSignonStatus.ps1)

```powershell
#Get-PawAtAutomaticRestartSignonStatus.ps1
# Description: Audits Administrative Templates: Disable Windows Automatic Restart Sign-On (ARSO) for PAWs.

Write-Host "--- Auditing Administrative Templates: Disable Windows Automatic Restart Sign-On (ARSO) for PAWs ---" -ForegroundColor Cyan
$script:Vulnerable = $false

$TargetKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$ValueName = "DisableAutomaticRestartSignOn"
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
* **CIS Benchmark**: CIS Microsoft Windows Client Benchmark: Section 18.10.82.2
* **ANSSI Active Directory Hardening Guide**: Baseline security parameters for managed Windows environments
* **Microsoft Security Baseline**: Recommended administrative template and component restrictions
