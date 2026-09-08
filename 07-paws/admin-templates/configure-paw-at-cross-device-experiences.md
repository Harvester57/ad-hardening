# [REQ-PAW-174] Administrative Templates: Disable Cross-Device Experiences for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration.
* **Operating Systems**: Windows 10 Enterprise (1607+) and Windows 11 Enterprise.

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**:
  * `HKLM\SOFTWARE\Policies\Microsoft\Windows\System\EnableCdp` = `0`

---

## Rationale
The Connected Devices Platform (CDP) coordinates cross-device application states and task handoffs over cloud synchronization and Bluetooth beacons. In enterprise environments, this introduces unmanaged synchronization pathways between managed corporate systems and external personal consumer devices.

---

## Legacy Impact & Compatibility
* **Operational Impact**: Cross-device features such as 'Continue on PC' from companion mobile devices or shared browser sessions will be unavailable.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to PAWs Organizational Unit (e.g., `GPO_Hardening_PAW`).
3. Configure the following policies:

* Navigate to: `Computer Configuration\Policies\Administrative Templates\System\Cross-Device Experiences`
  * **Continue experiences on this device**: Set to `Disabled`

4. Link the GPO to the appropriate Organizational Unit and verify replication.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to configure the administrative template registry values:

[Download Script: Configure-PawAtCrossDeviceExperiences.ps1](../implementation_scripts/Configure-PawAtCrossDeviceExperiences.ps1)

```powershell
#Configure-PawAtCrossDeviceExperiences.ps1
# Description: Configures Administrative Templates: Disable Cross-Device Experiences for PAWs.

Write-Host "Configuring Administrative Templates: Disable Cross-Device Experiences for PAWs..." -ForegroundColor Cyan

if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableCdp" -Value 0 -Type DWord -Force

Write-Host "[+] Administrative Templates: Disable Cross-Device Experiences for PAWs applied successfully." -ForegroundColor Green
```

*To verify the configuration:*

[Download Script: Get-PawAtCrossDeviceExperiencesStatus.ps1](../audit_scripts/Get-PawAtCrossDeviceExperiencesStatus.ps1)

```powershell
#Get-PawAtCrossDeviceExperiencesStatus.ps1
# Description: Audits Administrative Templates: Disable Cross-Device Experiences for PAWs.

Write-Host "--- Auditing Administrative Templates: Disable Cross-Device Experiences for PAWs ---" -ForegroundColor Cyan
$script:Vulnerable = $false

$TargetKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
$ValueName = "EnableCdp"
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
* **CIS Benchmark**: CIS Microsoft Windows Client Benchmark: Section 18.9.19.6
* **ANSSI Active Directory Hardening Guide**: Baseline security parameters for managed Windows environments
* **Microsoft Security Baseline**: Recommended administrative template and component restrictions
