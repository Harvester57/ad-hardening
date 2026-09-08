# [REQ-PAW-176] Administrative Templates: Block Custom SSPs and APs from Loading into LSASS for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration.
* **Operating Systems**: Windows 10 Enterprise (1607+) and Windows 11 Enterprise.

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * `HKLM\SOFTWARE\Policies\Microsoft\Windows\System\AllowCustomSSPsAPs` = `0`

---

## Rationale
Security Support Providers (SSPs) and Authentication Packages (APs) execute inside the Local Security Authority Subsystem Service (lsass.exe). Threat actors frequently register malicious SSP DLLs in the registry to achieve persistent credential harvesting and memory dumping. Disabling custom SSP loading blocks third-party DLLs from injecting into LSASS.

---

## Legacy Impact & Compatibility
* **Operational Impact**: Third-party authentication software or legacy smartcard drivers that inject custom SSP DLLs into LSASS will be blocked from loading. Modern providers must support Microsoft Credential Provider architecture.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to PAWs Organizational Unit (e.g., `GPO_Hardening_PAW`).
3. Configure the following policies:

* Navigate to: `Computer Configuration\Policies\Administrative Templates\System\Local Security Authority`
  * **Allow Custom SSPs and APs to be loaded into LSASS**: Set to `Disabled`

4. Link the GPO to the appropriate Organizational Unit and verify replication.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to configure the administrative template registry values:

[Download Script: Configure-PawAtLsaCustomSsps.ps1](../implementation_scripts/Configure-PawAtLsaCustomSsps.ps1)

```powershell
#Configure-PawAtLsaCustomSsps.ps1
# Description: Configures Administrative Templates: Block Custom SSPs and APs from Loading into LSASS for PAWs.

Write-Host "Configuring Administrative Templates: Block Custom SSPs and APs from Loading into LSASS for PAWs..." -ForegroundColor Cyan

if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "AllowCustomSSPsAPs" -Value 0 -Type DWord -Force

Write-Host "[+] Administrative Templates: Block Custom SSPs and APs from Loading into LSASS for PAWs applied successfully." -ForegroundColor Green
```

*To verify the configuration:*

[Download Script: Get-PawAtLsaCustomSspsStatus.ps1](../audit_scripts/Get-PawAtLsaCustomSspsStatus.ps1)

```powershell
#Get-PawAtLsaCustomSspsStatus.ps1
# Description: Audits Administrative Templates: Block Custom SSPs and APs from Loading into LSASS for PAWs.

Write-Host "--- Auditing Administrative Templates: Block Custom SSPs and APs from Loading into LSASS for PAWs ---" -ForegroundColor Cyan
$script:Vulnerable = $false

$TargetKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
$ValueName = "AllowCustomSSPsAPs"
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
* **CIS Benchmark**: CIS Microsoft Windows Client Benchmark: Section 18.9.26.1; ANSSI R38
* **ANSSI Active Directory Hardening Guide**: Baseline security parameters for managed Windows environments
* **Microsoft Security Baseline**: Recommended administrative template and component restrictions
