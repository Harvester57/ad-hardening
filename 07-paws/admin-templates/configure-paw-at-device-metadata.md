# [REQ-PAW-172] Administrative Templates: Prevent Device Metadata Retrieval from Network for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration.
* **Operating Systems**: Windows 10 Enterprise (1607+) and Windows 11 Enterprise.

---

## Implementation Details
* **Priority**: Low
* **GPO Path / Registry Location**:
  * `HKLM\SOFTWARE\Policies\Microsoft\Windows\Device Metadata\PreventDeviceMetadataFromNetwork` = `1`

---

## Rationale
Prevents the operating system from searching Windows Update and Microsoft public servers for device metadata, icons, and manufacturer information when new peripheral hardware is connected. This reduces unnecessary external telemetry and prevents information disclosure about attached hardware assets.

---

## Legacy Impact & Compatibility
* **Operational Impact**: Custom peripheral icons and detailed hardware descriptions in the 'Devices and Printers' folder will revert to generic device symbols.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to PAWs Organizational Unit (e.g., `GPO_Hardening_PAW`).
3. Configure the following policies:

* Navigate to: `Computer Configuration\Policies\Administrative Templates\System\Device Installation`
  * **Prevent device metadata retrieval from the Internet**: Set to `Enabled`

4. Link the GPO to the appropriate Organizational Unit and verify replication.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to configure the administrative template registry values:

[Download Script: Configure-PawAtDeviceMetadata.ps1](../implementation_scripts/Configure-PawAtDeviceMetadata.ps1)

```powershell
#Configure-PawAtDeviceMetadata.ps1
# Description: Configures Administrative Templates: Prevent Device Metadata Retrieval from Network for PAWs.

Write-Host "Configuring Administrative Templates: Prevent Device Metadata Retrieval from Network for PAWs..." -ForegroundColor Cyan

if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Name "PreventDeviceMetadataFromNetwork" -Value 1 -Type DWord -Force

Write-Host "[+] Administrative Templates: Prevent Device Metadata Retrieval from Network for PAWs applied successfully." -ForegroundColor Green
```

*To verify the configuration:*

[Download Script: Get-PawAtDeviceMetadataStatus.ps1](../audit_scripts/Get-PawAtDeviceMetadataStatus.ps1)

```powershell
#Get-PawAtDeviceMetadataStatus.ps1
# Description: Audits Administrative Templates: Prevent Device Metadata Retrieval from Network for PAWs.

Write-Host "--- Auditing Administrative Templates: Prevent Device Metadata Retrieval from Network for PAWs ---" -ForegroundColor Cyan
$script:Vulnerable = $false

$TargetKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata"
$ValueName = "PreventDeviceMetadataFromNetwork"
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
* **CIS Benchmark**: CIS Microsoft Windows Client Benchmark: Section 18.9.7.2
* **ANSSI Active Directory Hardening Guide**: Baseline security parameters for managed Windows environments
* **Microsoft Security Baseline**: Recommended administrative template and component restrictions
