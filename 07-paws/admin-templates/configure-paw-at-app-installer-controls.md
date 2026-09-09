# [REQ-PAW-188] Administrative Templates: App Installer Protocol and Execution Controls for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration. *(For Tier 2 Client Workstations and Member Servers, refer to baseline [REQ-END-199](../../08-endpoints/admin-templates/configure-end-at-app-installer-controls.md)).*
* **Operating Systems**: Windows 10 Enterprise (1709+) and Windows 11 Enterprise.

---

## Implementation Details
* **Priority**: High
* **GPO Paths / Registry Locations**:
  * **Disable App Installer ms-appinstaller Protocol**:
    * GPO Path: `Computer Configuration\Policies\Administrative Templates\Windows Components\App Installer\Enable App Installer ms-appinstaller protocol` -> **Disabled**
    * Registry Path: `HKLM\SOFTWARE\Policies\Microsoft\Windows\AppInstaller`
    * Value Name: `EnableMSAppInstallerProtocol`
    * Value Type: `REG_DWORD`
    * Value Data: `0` (Disabled)
  * **Disable App Installer Experimental Features**:
    * GPO Path: `Computer Configuration\Policies\Administrative Templates\Windows Components\App Installer\Enable App Installer Experimental Features` -> **Disabled**
    * Registry Path: `HKLM\SOFTWARE\Policies\Microsoft\Windows\AppInstaller`
    * Value Name: `EnableExperimentalFeatures`
    * Value Type: `REG_DWORD`
    * Value Data: `0` (Disabled)
  * **Disable App Installer Hash Override**:
    * GPO Path: `Computer Configuration\Policies\Administrative Templates\Windows Components\App Installer\Enable App Installer Hash Override` -> **Disabled**
    * Registry Path: `HKLM\SOFTWARE\Policies\Microsoft\Windows\AppInstaller`
    * Value Name: `EnableHashOverride`
    * Value Type: `REG_DWORD`
    * Value Data: `0` (Disabled)
  * **Disable Local Archive Malware Scan Override**:
    * GPO Path: `Computer Configuration\Policies\Administrative Templates\Windows Components\App Installer\Enable App Installer Local Archive Malware Scan Override` -> **Disabled**
    * Registry Path: `HKLM\SOFTWARE\Policies\Microsoft\Windows\AppInstaller`
    * Value Name: `EnableLocalArchiveMalwareScanOverride`
    * Value Type: `REG_DWORD`
    * Value Data: `0` (Disabled)
  * **Enforce Microsoft Store Certificate Pinning**:
    * GPO Path: `Computer Configuration\Policies\Administrative Templates\Windows Components\App Installer\Enable App Installer Microsoft Store Source Certificate Validation Bypass` -> **Disabled**
    * Registry Path: `HKLM\SOFTWARE\Policies\Microsoft\Windows\AppInstaller`
    * Value Name: `EnableBypassCertificatePinningForMicrosoftStore`
    * Value Type: `REG_DWORD`
    * Value Data: `0` (Disabled / Bypass disallowed)

---

## Rationale
Privileged Access Workstations (PAWs) serve as the dedicated platform for Tier 0 Active Directory operations. Protecting the workstation from remote initial access vectors is paramount. The Windows App Installer protocol and package execution mechanisms present a severe vector for untrusted payload delivery that must be comprehensively disabled.

### 1. Eliminating Drive-By Initial Access Vectors on Tier 0 Hosts
The `ms-appinstaller://` URI scheme enables web-driven execution of MSIX packages:
* Threat actors targeting enterprise infrastructure frequently weaponize `ms-appinstaller` in spear-phishing or watering-hole attacks to bypass browser controls and deliver initial-access implants (such as BatLoader, Emotet, or custom beacon payloads).
* On a PAW, any execution of untrusted third-party code threatens to compromise directory credentials, LSA secrets, and Kerberos Ticket Granting Service keys.
* Disabling `EnableMSAppInstallerProtocol` completely unbinds the URI protocol handler, ensuring that even if an administrator encounters a malicious URI, the operating system refuses to invoke `AppInstaller.exe`.

### 2. Enforcing Strict Package Verification and Integrity
In the unlikely event that App Installer binaries are invoked on a PAW, security bypass mechanisms must be strictly disabled:
* **Prohibiting Hash Overrides (`EnableHashOverride = 0`)**: Enforces cryptographic package signature and digest integrity, preventing installation of modified packages.
* **Mandatory Malware Scanning (`EnableLocalArchiveMalwareScanOverride = 0`)**: Guarantees that local archive extraction is inspected by Microsoft Defender Antivirus through AMSI.
* **Certificate Pinning Validation (`EnableBypassCertificatePinningForMicrosoftStore = 0`)**: Prevents untrusted root certificates or TLS proxy inspection from spoofing Store endpoints.
* **Suppressing Experimental Code Paths (`EnableExperimentalFeatures = 0`)**: Eliminates unverified developer features that may contain privilege escalation bugs.

### 3. MITRE ATT&CK Mapping
* **T1218 - System Binary Proxy Execution**: Proxying execution through Microsoft App Installer.
* **T1566.002 - Phishing: Spearphishing Link**: Delivery of malicious package links via phishing channels.
* **T1204.001 - User Execution: Malicious Link**: User-initiated package execution via browser links.
* **T1553.005 - Subvert Trust Controls: Treat As Untrusted**: Enforcing cryptographic package validation.

---

## Legacy Impact & Compatibility
* **Operational Impact**: None. PAWs are dedicated to directory administration and never utilize consumer or web-delivered MSIX applications.
* **Administrative Tooling**: Administrative tools (such as RSAT, Azure CLI, and PowerShell modules) are installed via enterprise-managed channels and standard Windows feature installations, remaining unaffected.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to the PAWs Organizational Unit (e.g., `GPO_Hardening_PAW`).
3. Configure the following policies:

* Navigate to: `Computer Configuration\Policies\Administrative Templates\Windows Components\App Installer`
  * **Enable App Installer ms-appinstaller protocol**: Set to `Disabled`
  * **Enable App Installer Experimental Features**: Set to `Disabled`
  * **Enable App Installer Hash Override**: Set to `Disabled`
  * **Enable App Installer Local Archive Malware Scan Override**: Set to `Disabled`
  * **Enable App Installer Microsoft Store Source Certificate Validation Bypass**: Set to `Disabled`

4. Link the GPO to the PAW Organizational Unit and enforce policy replication using `gpupdate /force`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to configure the administrative template registry values:

[Download Script: Configure-PawAtAppInstallerControls.ps1](../implementation_scripts/Configure-PawAtAppInstallerControls.ps1)

```powershell
#Configure-PawAtAppInstallerControls.ps1
# Description: Configures Administrative Templates: App Installer Protocol and Execution Controls for PAWs.

Write-Host "Configuring Administrative Templates: App Installer Protocol and Execution Controls for PAWs..." -ForegroundColor Cyan

if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller" -Name "EnableExperimentalFeatures" -Value 0 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller" -Name "EnableHashOverride" -Value 0 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller" -Name "EnableLocalArchiveMalwareScanOverride" -Value 0 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller" -Name "EnableBypassCertificatePinningForMicrosoftStore" -Value 0 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller" -Name "EnableMSAppInstallerProtocol" -Value 0 -Type DWord -Force

Write-Host "[+] Administrative Templates: App Installer Protocol and Execution Controls for PAWs applied successfully." -ForegroundColor Green
```

*To verify the configuration:*

[Download Script: Get-PawAtAppInstallerControlsStatus.ps1](../audit_scripts/Get-PawAtAppInstallerControlsStatus.ps1)

```powershell
#Get-PawAtAppInstallerControlsStatus.ps1
# Description: Audits Administrative Templates: App Installer Protocol and Execution Controls for PAWs.

Write-Host "--- Auditing Administrative Templates: App Installer Protocol and Execution Controls for PAWs ---" -ForegroundColor Cyan
$script:Vulnerable = $false

$TargetKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller"
$ValueName = "EnableExperimentalFeatures"
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

$TargetKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller"
$ValueName = "EnableHashOverride"
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

$TargetKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller"
$ValueName = "EnableLocalArchiveMalwareScanOverride"
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

$TargetKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller"
$ValueName = "EnableBypassCertificatePinningForMicrosoftStore"
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

$TargetKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller"
$ValueName = "EnableMSAppInstallerProtocol"
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
* **CIS Benchmark**: CIS Microsoft Windows 10 Enterprise Benchmark: Section 18.10.18.2, 18.10.18.3, 18.10.18.4, 18.10.18.5, 18.10.18.6; CIS Microsoft Windows 11 Enterprise Benchmark: Section 18.10.18.2, 18.10.18.3, 18.10.18.4, 18.10.18.5, 18.10.18.6
* **DISA STIG**: Windows 10 STIG Rule WN10-CC-000340, Windows 11 STIG Rule WN11-CC-000340
* **Microsoft Security Advisory**: Disabling the MSIX ms-appinstaller protocol scheme (CVE-2021-43890)
* **Microsoft Privileged Access Workstation Guidance**: PAW Application Whitelisting and Installation Hardening
