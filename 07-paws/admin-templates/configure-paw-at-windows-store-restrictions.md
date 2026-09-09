# [REQ-PAW-194] Administrative Templates: Windows Store Updates and OS Upgrade Restrictions for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration. *(For Tier 2 Client Workstations and Member Servers, refer to baseline [REQ-END-205](../../08-endpoints/admin-templates/configure-end-at-windows-store-restrictions.md)).*
* **Operating Systems**: Windows 10 Enterprise (1607+) and Windows 11 Enterprise.

---

## Implementation Details
* **Priority**: Medium
* **GPO Paths / Registry Locations**:
  * **Allow Automatic Download and Installation of Store App Updates**:
    * GPO Path: `Computer Configuration\Policies\Administrative Templates\Windows Components\Store\Turn off Automatic Download and Install of updates` -> **Disabled** (Enforces automatic updates)
    * Registry Path: `HKLM\SOFTWARE\Policies\Microsoft\WindowsStore`
    * Value Name: `AutoDownload`
    * Value Type: `REG_DWORD`
    * Value Data: `4` (Automatic update installation enabled)
  * **Turn off the offer to update to the latest version of Windows**:
    * GPO Path: `Computer Configuration\Policies\Administrative Templates\Windows Components\Store\Turn off the offer to update to the latest version of Windows` -> **Enabled**
    * Registry Path: `HKLM\SOFTWARE\Policies\Microsoft\WindowsStore`
    * Value Name: `DisableOSUpgrade`
    * Value Type: `REG_DWORD`
    * Value Data: `1` (Enabled / Block consumer OS upgrade offers)

---

## Rationale
Privileged Access Workstations (PAWs) execute mission-critical directory administration tools. Essential system management utilities (such as Windows Terminal and system runtime dependencies) are maintained through modern packaging pipelines, requiring rigorous patch hygiene without exposing the privileged environment to uncoordinated operating system upgrades.

### 1. Ensuring Patch Currency for Pre-Installed Administrative Components
Even in minimal Tier 0 installations, modern Windows builds include foundational packages:
* Core utilities such as Windows Terminal, PowerShell 7 packages, and underlying runtime components (like WebP libraries and .NET AppContainer dependencies) require regular security updates.
* If automatic updates are prohibited on a PAW, system packages remain vulnerable to publicly disclosed vulnerabilities, potentially allowing local privilege escalation or remote code execution.
* Setting `AutoDownload = 4` (disabling "Turn off Automatic Download and Install of updates") ensures that any packaged components present on the PAW receive timely security patches from Microsoft update channels.

### 2. Guarding Tier 0 Systems Against Unmanaged OS Migrations
Uncontrolled operating system feature upgrades present severe operational risks:
* Upgrading an administrative workstation across major OS releases (e.g., Windows 10 to Windows 11) outside of a tested enterprise deployment can break credential isolation controls (Credential Guard, WDAC policies, or smart card authentication drivers).
* Setting `DisableOSUpgrade = 1` completely suppresses consumer upgrade offers from the Windows Store, ensuring that PAWs undergo major version migrations only through tested, validated enterprise staging processes.

### 3. MITRE ATT&CK Mapping
* **T1195.002 - Supply Chain Compromise: Compromised Software Dependencies**: Patching system runtime components to eliminate known CVEs.
* **T1489 - Service Stop / System Disruption**: Preventing uncontrolled OS migrations that disrupt administrative operations.

---

## Legacy Impact & Compatibility
* **Operational Impact**: None. Administrative workflows on PAWs are maintained with patched components while major OS version upgrades are strictly scheduled.
* **Administrative Tooling**: Essential administrative command-line tools remain stable and secure.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to the PAWs Organizational Unit (e.g., `GPO_Hardening_PAW`).
3. Configure the following policies:

* Navigate to: `Computer Configuration\Policies\Administrative Templates\Windows Components\Store`
  * **Turn off Automatic Download and Install of updates**: Set to `Disabled` (Ensures updates are downloaded automatically)
* Navigate to: `Computer Configuration\Policies\Administrative Templates\Windows Components\Store`
  * **Turn off the offer to update to the latest version of Windows**: Set to `Enabled`

4. Link the GPO to the PAW Organizational Unit and enforce policy replication using `gpupdate /force`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to configure the administrative template registry values:

[Download Script: Configure-PawAtWindowsStoreRestrictions.ps1](../implementation_scripts/Configure-PawAtWindowsStoreRestrictions.ps1)

```powershell
#Configure-PawAtWindowsStoreRestrictions.ps1
# Description: Configures Administrative Templates: Windows Store Updates and OS Upgrade Restrictions for PAWs.

Write-Host "Configuring Administrative Templates: Windows Store Updates and OS Upgrade Restrictions for PAWs..." -ForegroundColor Cyan

if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Name "AutoDownload" -Value 4 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Name "DisableOSUpgrade" -Value 1 -Type DWord -Force

Write-Host "[+] Administrative Templates: Windows Store Updates and OS Upgrade Restrictions for PAWs applied successfully." -ForegroundColor Green
```

*To verify the configuration:*

[Download Script: Get-PawAtWindowsStoreRestrictionsStatus.ps1](../audit_scripts/Get-PawAtWindowsStoreRestrictionsStatus.ps1)

```powershell
#Get-PawAtWindowsStoreRestrictionsStatus.ps1
# Description: Audits Administrative Templates: Windows Store Updates and OS Upgrade Restrictions for PAWs.

Write-Host "--- Auditing Administrative Templates: Windows Store Updates and OS Upgrade Restrictions for PAWs ---" -ForegroundColor Cyan
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
* **CIS Benchmark**: CIS Microsoft Windows 10 Enterprise Benchmark: Section 18.10.87.1, Section 18.10.87.2; CIS Microsoft Windows 11 Enterprise Benchmark: Section 18.10.87.1, Section 18.10.87.2
* **DISA STIG**: Windows 10 STIG Rule WN10-CC-000350, Windows 11 STIG Rule WN11-CC-000350
* **Microsoft Privileged Access Workstation Guidance**: Tier 0 Software Maintenance and Lifecycle Standards
