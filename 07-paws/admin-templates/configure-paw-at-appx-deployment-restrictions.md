# [REQ-PAW-182] Administrative Templates: App Package Deployment Restrictions for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration. *(For Tier 2 Client Workstations and Member Servers, refer to baseline [REQ-END-193](../../08-endpoints/admin-templates/configure-end-at-appx-deployment-restrictions.md)).*
* **Operating Systems**: Windows 10 Enterprise (1607+) and Windows 11 Enterprise.

---

## Implementation Details
* **Priority**: High
* **GPO Paths / Registry Locations**:
  * **Not allow per-user unsigned packages to install by default**:
    * GPO Path: `Computer Configuration\Policies\Administrative Templates\Windows Components\App Package Deployment\Not allow per-user unsigned packages to install by default (requires explicitly allow per install)` -> **Enabled**
    * Registry Path: `HKLM\SOFTWARE\Policies\Microsoft\Windows\Appx`
    * Value Name: `DisablePerUserUnsignedPackagesByDefault`
    * Value Type: `REG_DWORD`
    * Value Data: `1` (Enabled / Prohibit unsigned packages)
  * **Prevent non-admin users from installing packaged Windows apps**:
    * GPO Path: `Computer Configuration\Policies\Administrative Templates\Windows Components\App Package Deployment\Prevent non-admin users from installing packaged Windows apps` -> **Enabled**
    * Registry Path: `HKLM\SOFTWARE\Policies\Microsoft\Windows\Appx`
    * Value Name: `BlockNonAdminUserInstall`
    * Value Type: `REG_DWORD`
    * Value Data: `1` (Enabled / Restrict to administrators)

---

## Rationale
Privileged Access Workstations (PAWs) are dedicated exclusively to directory administration and Tier 0 infrastructure management. Application installation on a PAW must adhere to the strictest change management, code signing, and administrative boundaries.

### 1. Eliminating Untrusted Package Execution on Tier 0 Hosts
Modern Windows AppX and MSIX packages can introduce unauthorized code into user profiles:
* Standard user profiles allow modern packaged applications to execute without requiring full machine-wide installation. On a PAW, allowing any user-level package installation introduces severe risks of malicious software sideloading, persistence establishment, and evasive code execution.
* Adversaries target privileged workstations with crafted application bundles designed to evade standard application whitelisting rules by executing from user-writable AppData subdirectories.
* Setting `BlockNonAdminUserInstall = 1` enforces that standard users cannot register or execute modern application packages. All installed utilities must be provisioned machine-wide by administrators or enterprise management systems.

### 2. Prohibiting Unsigned Package Execution
Unsigned or developer-mode package deployment bypasses standard code integrity mechanisms:
* An operator or rogue script could attempt to sideload unverified utility packages containing unsigned binaries or modified libraries.
* Setting `DisablePerUserUnsignedPackagesByDefault = 1` guarantees that Windows rejects unsigned modern packages, requiring explicit, cryptographically verifiable code signing from trusted enterprise roots or Microsoft before any package can be registered.

### 3. MITRE ATT&CK Mapping
* **T1059 - Command and Scripting Interpreter**: Executing living-off-the-land scripts via modern application packages.
* **T1546 - Event Triggered Execution**: Using package lifecycle triggers for persistent execution.
* **T1204.002 - User Execution: Malicious File**: Launching unauthorized packaged software on privileged hosts.
* **T1553.002 - Subvert Trust Controls: Code Signing**: Enforcing rigorous digital signature verification on all executable packages.

---

## Legacy Impact & Compatibility
* **Operational Impact**: None. PAWs are provisioned with a minimal, hardened set of administrative tools (RSAT, administrative PowerShell modules, and directory management consoles). Consumer or developer packaged applications have no role in Tier 0 operations.
* **Administrative Tooling**: Management tools installed via official enterprise packages or standard Windows Feature on Demand (FoD) packages install and operate without disruption.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to the PAWs Organizational Unit (e.g., `GPO_Hardening_PAW`).
3. Configure the following policies:

* Navigate to: `Computer Configuration\Policies\Administrative Templates\Windows Components\App Package Deployment`
  * **Not allow per-user unsigned packages to install by default (requires explicitly allow per install)**: Set to `Enabled`
* Navigate to: `Computer Configuration\Policies\Administrative Templates\Windows Components\App Package Deployment`
  * **Prevent non-admin users from installing packaged Windows apps**: Set to `Enabled`

4. Link the GPO to the PAW Organizational Unit and enforce policy replication using `gpupdate /force`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to configure the administrative template registry values:

[Download Script: Configure-PawAtAppxDeploymentRestrictions.ps1](../implementation_scripts/Configure-PawAtAppxDeploymentRestrictions.ps1)

```powershell
#Configure-PawAtAppxDeploymentRestrictions.ps1
# Description: Configures Administrative Templates: App Package Deployment Restrictions for PAWs.

Write-Host "Configuring Administrative Templates: App Package Deployment Restrictions for PAWs..." -ForegroundColor Cyan

if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Appx")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Appx" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Appx" -Name "DisablePerUserUnsignedPackagesByDefault" -Value 1 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Appx" -Name "BlockNonAdminUserInstall" -Value 1 -Type DWord -Force

Write-Host "[+] Administrative Templates: App Package Deployment Restrictions for PAWs applied successfully." -ForegroundColor Green
```

*To verify the configuration:*

[Download Script: Get-PawAtAppxDeploymentRestrictionsStatus.ps1](../audit_scripts/Get-PawAtAppxDeploymentRestrictionsStatus.ps1)

```powershell
#Get-PawAtAppxDeploymentRestrictionsStatus.ps1
# Description: Audits Administrative Templates: App Package Deployment Restrictions for PAWs.

Write-Host "--- Auditing Administrative Templates: App Package Deployment Restrictions for PAWs ---" -ForegroundColor Cyan
$script:Vulnerable = $false

$TargetKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Appx"
$ValueName = "DisablePerUserUnsignedPackagesByDefault"
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

$TargetKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Appx"
$ValueName = "BlockNonAdminUserInstall"
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
* **CIS Benchmark**: CIS Microsoft Windows 10 Enterprise Benchmark: Section 18.10.14.1, Section 18.10.14.2; CIS Microsoft Windows 11 Enterprise Benchmark: Section 18.10.14.1, Section 18.10.14.2
* **DISA STIG**: Windows 10 STIG Rule WN10-CC-000330, Windows 11 STIG Rule WN11-CC-000330
* **ANSSI Active Directory Hardening Guide**: Section 3.3 (Application Whitelisting and Code Signing Enforcement)
* **Microsoft Privileged Access Workstation Guidance**: PAW Application Whitelisting and Software Execution Baseline
