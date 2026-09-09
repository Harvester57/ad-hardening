# [REQ-END-186] Administrative Templates: Restrict Internet Communication and Web Downloads

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers. *(For Tier 0 Privileged Access Workstations, refer to tightened baseline [REQ-PAW-175](../../07-paws/admin-templates/configure-paw-at-internet-communication.md); for Domain Controllers, refer to [REQ-DC-027](../../02-domain-controllers/configure-telemetry-privacy.md)).*
* **Operating Systems**: Windows 10 Enterprise/Professional (all supported builds), Windows 11 Enterprise/Pro, Windows Server 2016, 2019, 2022, and 2025.

---

## Implementation Details
* **Priority**: Medium
* **GPO Paths / Registry Locations**:
  * **Turn off downloading of print drivers over HTTP**:
    * GPO Path: `Computer Configuration\Policies\Administrative Templates\System\Internet Communication Management\Internet Communication settings\Turn off downloading of print drivers over HTTP` -> **Enabled**
    * Registry Path: `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers`
    * Value Name: `DisableWebPnPDownload`
    * Value Type: `REG_DWORD`
    * Value Data: `1` (Disabled / Block HTTP print driver downloads)
  * **Turn off Internet download for Web publishing and online ordering wizards**:
    * GPO Path: `Computer Configuration\Policies\Administrative Templates\System\Internet Communication Management\Internet Communication settings\Turn off Internet download for Web publishing and online ordering wizards` -> **Enabled**
    * Registry Path: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer`
    * Value Name: `NoWebServices`
    * Value Type: `REG_DWORD`
    * Value Data: `1` (Disabled / Block web wizard downloads)

---

## Rationale
The Windows operating system includes several legacy features designed to download supplemental drivers, wizard components, and third-party web provider templates over unauthenticated internet connections. In enterprise environments, these automated internet interactions expose endpoints to remote code execution and data exfiltration.

### 1. Print Driver Delivery Security and PrintNightmare Mitigations
Web Point and Print allows Windows clients to query web print servers and automatically download printer driver packages across unencrypted HTTP channels:
* **Adversary-in-the-Middle (AiTM) Driver Tampering**: Because HTTP lacks cryptographic integrity protection, an adversary positioned on the local network or transit path can intercept the driver request and inject modified DLLs or INF configuration files.
* **SYSTEM Privilege Escalation via Print Spooler**: Print drivers execute in ring 0 kernel space or inside the highly privileged Print Spooler service (`spoolsv.exe`, operating as `NT AUTHORITY\SYSTEM`). Vulnerabilities such as PrintNightmare (CVE-2021-1675, CVE-2021-34527) demonstrated that malicious print drivers can achieve immediate, unconstrained code execution on the client host.
* Setting `DisableWebPnPDownload = 1` prevents the Windows print subsystem from ever requesting or downloading printer driver packages over HTTP. All driver installations must be sourced from the local Windows Driver Store or deployed via authenticated, enterprise-managed administrative software.

### 2. Elimination of Unauthenticated Web Wizard Channels
Windows Explorer includes legacy wizards for "Publish to Web" and "Order Prints Online" that dynamically fetch provider manifests and schema files from the internet:
* **Data Exfiltration and Metadata Leakage**: These wizards initiate unsolicited outbound HTTP connections that transmit system environmental parameters, network identifiers, and user metadata to external servers.
* **Phishing and Rogue Provider Redirection**: In unhardened configurations, obsolete wizard schemas could be weaponized to present fraudulent upload forms to users, facilitating credential harvesting or sensitive document exfiltration.
* Setting `NoWebServices = 1` eliminates the retrieval of external provider lists, ensuring Windows Explorer does not establish unmanaged internet connections during file browsing.

### 3. MITRE ATT&CK Mapping
* **T1574.002 - Hijack Execution Flow: DLL Side-Loading / Driver Sideloading**: Injecting malicious driver components via unauthenticated HTTP Point and Print.
* **T1068 - Exploitation for Privilege Escalation**: Abusing print driver installation mechanisms to execute code in the context of `NT AUTHORITY\SYSTEM`.
* **T1048 - Exfiltration Over Alternative Protocol**: Unauthorized transmission of sensitive data using legacy web publishing channels.

---

## Legacy Impact & Compatibility
* **Corporate Printing Infrastructure**: Enterprise print environments utilize Active Directory Domain Services (AD DS) shared printers or modern print management platforms (such as Universal Print, PaperCut, or PrinterLogic) that deliver pre-packaged, digitally signed print drivers. Blocking HTTP driver downloads does not affect internal print queues managed via authenticated RPC/SMB.
* **Home and Remote Printing**: Teleworkers connecting to personal home printers must ensure that vendor drivers are pre-installed via manufacturer installers or Windows Update rather than attempting Web Point and Print over HTTP.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to workstations and member servers (e.g., `GPO_Hardening_Endpoints`).
3. Configure the following policies:

* Navigate to: `Computer Configuration\Policies\Administrative Templates\System\Internet Communication Management\Internet Communication settings`
  * **Turn off downloading of print drivers over HTTP**: Set to `Enabled`
* Navigate to: `Computer Configuration\Policies\Administrative Templates\System\Internet Communication Management\Internet Communication settings`
  * **Turn off Internet download for Web publishing and online ordering wizards**: Set to `Enabled`

4. Link the GPO to the appropriate Organizational Unit and verify policy enforcement using `gpupdate /force`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to configure the administrative template registry values:

[Download Script: Configure-EndAtInternetCommunication.ps1](../implementation_scripts/Configure-EndAtInternetCommunication.ps1)

```powershell
#Configure-EndAtInternetCommunication.ps1
# Description: Configures Administrative Templates: Restrict Internet Communication and Web Downloads.

Write-Host "Configuring Administrative Templates: Restrict Internet Communication and Web Downloads..." -ForegroundColor Cyan

if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" -Name "DisableWebPnPDownload" -Value 1 -Type DWord -Force

if (-not (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoWebServices" -Value 1 -Type DWord -Force

Write-Host "[+] Administrative Templates: Restrict Internet Communication and Web Downloads applied successfully." -ForegroundColor Green
```

*To verify the configuration:*

[Download Script: Get-EndAtInternetCommunicationStatus.ps1](../audit_scripts/Get-EndAtInternetCommunicationStatus.ps1)

```powershell
#Get-EndAtInternetCommunicationStatus.ps1
# Description: Audits Administrative Templates: Restrict Internet Communication and Web Downloads.

Write-Host "--- Auditing Administrative Templates: Restrict Internet Communication and Web Downloads ---" -ForegroundColor Cyan
$script:Vulnerable = $false

$TargetKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers"
$ValueName = "DisableWebPnPDownload"
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

$TargetKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
$ValueName = "NoWebServices"
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
* **CIS Benchmark**: CIS Microsoft Windows 10 Enterprise Benchmark: Section 18.9.30.2, Section 18.9.30.3; CIS Microsoft Windows 11 Enterprise Benchmark: Section 18.9.30.2, Section 18.9.30.3; CIS Windows Server Benchmark: Section 18.9.30.2, Section 18.9.30.3
* **DISA STIG**: Windows 10 STIG Rules WN10-CC-000280, WN10-CC-000285; Windows 11 STIG Rules WN11-CC-000280, WN11-CC-000285
* **ANSSI Active Directory Hardening Guide**: Section 3.2 (Restricting unnecessary internet-facing services and protocols)
* **Microsoft Security Guidance**: Point and Print Hardening Rules (KB5005010 / CVE-2021-34527)
