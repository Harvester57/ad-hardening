# [REQ-END-193] Administrative Templates: App Package Deployment Restrictions

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers. *(For Tier 0 Privileged Access Workstations, refer to tightened baseline [REQ-PAW-182](../../07-paws/admin-templates/configure-paw-at-appx-deployment-restrictions.md)).*
* **Operating Systems**: Windows 10 Enterprise/Professional (all supported builds), Windows 11 Enterprise/Pro, Windows Server 2016, 2019, 2022, and 2025.

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
Modern Windows application packaging architectures (AppX and MSIX) allow software components to be registered and executed within user profile spaces. In unhardened environments, default deployment behaviors allow standard unprivileged users to install modern packaged applications without administrative oversight or UAC elevation.

### 1. AppX Package Abuse and Defense Evasion
Standard enterprise access controls often assume that software installation requires local administrative credentials:
* **Bypassing Traditional Application Control**: When standard users are permitted to install AppX/MSIX packages, they can deploy applications into per-user directories located under `%LocalAppData%\Packages`. If AppLocker or software restriction policies rely on standard path-based rules (such as permitting execution under `%ProgramFiles%` and restricting `%LocalAppData%`), packaged applications can circumvent these controls by executing inside AppContainer runtime sandboxes or leveraging Centennial desktop bridges.
* **Malicious Sideloading and Shadow IT**: Adversaries distribute malicious packaged applications carrying living-off-the-land binaries, script runners, or backdoors. When non-administrative users can register packages at will, adversaries can achieve execution without needing privilege escalation.
* **Unsigned Package Vulnerabilities**: Unsigned or self-signed AppX packages can be installed if developer or testing options are unmanaged, allowing tampered binaries to be loaded into user profiles.

### 2. Restricting Installation to Administrative Contexts
Enforcing AppX deployment restrictions establishes critical baseline governance:
* Setting `BlockNonAdminUserInstall = 1` ensures that standard users cannot invoke `Add-AppxPackage` or click modern application bundles to register software on the system. All package provisioning must be executed by local administrators, automated software deployment agents (such as Intune Management Extension or SCCM), or provisioned for all users via `DISM` / `Add-AppxProvisionedPackage`.
* Setting `DisablePerUserUnsignedPackagesByDefault = 1` guarantees that even if a per-user installation is initiated, unsigned packages are blocked by default, requiring explicit, audited administrative consent.

### 3. MITRE ATT&CK Mapping
* **T1059 - Command and Scripting Interpreter**: Sideloading malicious scripts or bridge executables via packaged AppX bundles.
* **T1546 - Event Triggered Execution**: Utilizing modern package registration triggers for user-level persistence.
* **T1204.002 - User Execution: Malicious File**: Unprivileged execution of rogue packaged applications.
* **T1553.002 - Subvert Trust Controls: Code Signing**: Enforcing package signature integrity.

---

## Legacy Impact & Compatibility
* **Centrally Managed Enterprise Deployments**: Applications deployed via enterprise tools (such as Microsoft Intune, MECM, or automated deployment scripts running under `SYSTEM` or administrative context) operate normally.
* **Non-Administrative User Experience**: Standard enterprise users will receive an access-denied notification if they attempt to install AppX, MSIX, or Windows Store application packages independently. Users requiring business software must request application deployment through official enterprise service catalogs.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to workstations and member servers (e.g., `GPO_Hardening_Endpoints`).
3. Configure the following policies:

* Navigate to: `Computer Configuration\Policies\Administrative Templates\Windows Components\App Package Deployment`
  * **Not allow per-user unsigned packages to install by default (requires explicitly allow per install)**: Set to `Enabled`
* Navigate to: `Computer Configuration\Policies\Administrative Templates\Windows Components\App Package Deployment`
  * **Prevent non-admin users from installing packaged Windows apps**: Set to `Enabled`

4. Link the GPO to the appropriate Organizational Unit and verify policy enforcement using `gpupdate /force`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to configure the administrative template registry values:

[Download Script: Configure-EndAtAppxDeploymentRestrictions.ps1](../implementation_scripts/Configure-EndAtAppxDeploymentRestrictions.ps1)

```powershell
#Configure-EndAtAppxDeploymentRestrictions.ps1
# Description: Configures Administrative Templates: App Package Deployment Restrictions.

Write-Host "Configuring Administrative Templates: App Package Deployment Restrictions..." -ForegroundColor Cyan

if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Appx")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Appx" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Appx" -Name "DisablePerUserUnsignedPackagesByDefault" -Value 1 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Appx" -Name "BlockNonAdminUserInstall" -Value 1 -Type DWord -Force

Write-Host "[+] Administrative Templates: App Package Deployment Restrictions applied successfully." -ForegroundColor Green
```

*To verify the configuration:*

[Download Script: Get-EndAtAppxDeploymentRestrictionsStatus.ps1](../audit_scripts/Get-EndAtAppxDeploymentRestrictionsStatus.ps1)

```powershell
#Get-EndAtAppxDeploymentRestrictionsStatus.ps1
# Description: Audits Administrative Templates: App Package Deployment Restrictions.

Write-Host "--- Auditing Administrative Templates: App Package Deployment Restrictions ---" -ForegroundColor Cyan
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
* **Microsoft Security Baseline**: Windows App Package Deployment Policy Baseline
