# [REQ-END-189] Administrative Templates: Disable Connected Standby Network Connectivity

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers.
* **Operating Systems**: Windows 10 (and above) Enterprise/Professional, Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**:
  * `HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9\DCSettingIndex` = `0`
  * `HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9\ACSettingIndex` = `0`

---

## Rationale
Connected Standby (Modern Standby) maintains active wireless and network interfaces while the operating system is suspended. This allows background applications to receive traffic and process incoming network packets, exposing devices to remote attacks and unauthorized network reconnaissance while unattended.

---

## Legacy Impact & Compatibility
* **Operational Impact**: Applications cannot receive real-time notifications or synchronize background data while the laptop lid is closed or during sleep states.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to workstations and member servers (e.g., `GPO_Hardening_Endpoints`).
3. Configure the following policies:

* Navigate to: `Computer Configuration\Policies\Administrative Templates\System\Power Management\Sleep Settings`
  * **Allow network connectivity during connected-standby (on battery)**: Set to `Disabled`
* Navigate to: `Computer Configuration\Policies\Administrative Templates\System\Power Management\Sleep Settings`
  * **Allow network connectivity during connected-standby (plugged in)**: Set to `Disabled`

4. Link the GPO to the appropriate Organizational Unit and verify replication.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to configure the administrative template registry values:

[Download Script: Configure-EndAtPowerConnectedStandby.ps1](../implementation_scripts/Configure-EndAtPowerConnectedStandby.ps1)

```powershell
#Configure-EndAtPowerConnectedStandby.ps1
# Description: Configures Administrative Templates: Disable Connected Standby Network Connectivity.

Write-Host "Configuring Administrative Templates: Disable Connected Standby Network Connectivity..." -ForegroundColor Cyan

if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9" -Name "DCSettingIndex" -Value 0 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9" -Name "ACSettingIndex" -Value 0 -Type DWord -Force

Write-Host "[+] Administrative Templates: Disable Connected Standby Network Connectivity applied successfully." -ForegroundColor Green
```

*To verify the configuration:*

[Download Script: Get-EndAtPowerConnectedStandbyStatus.ps1](../audit_scripts/Get-EndAtPowerConnectedStandbyStatus.ps1)

```powershell
#Get-EndAtPowerConnectedStandbyStatus.ps1
# Description: Audits Administrative Templates: Disable Connected Standby Network Connectivity.

Write-Host "--- Auditing Administrative Templates: Disable Connected Standby Network Connectivity ---" -ForegroundColor Cyan
$script:Vulnerable = $false

$TargetKey = "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9"
$ValueName = "DCSettingIndex"
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

$TargetKey = "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9"
$ValueName = "ACSettingIndex"
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
* **CIS Benchmark**: CIS Microsoft Windows Client Benchmark: Section 18.9.33.6.1, Section 18.9.33.6.2
* **ANSSI Active Directory Hardening Guide**: Baseline security parameters for managed Windows environments
* **Microsoft Security Baseline**: Recommended administrative template and component restrictions
