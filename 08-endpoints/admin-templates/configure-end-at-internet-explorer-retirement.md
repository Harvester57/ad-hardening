# [REQ-END-202] Administrative Templates: Internet Explorer 11 and Web Feeds Retirement Controls

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers. *(For Tier 0 Privileged Access Workstations, refer to tightened baseline [REQ-PAW-191](../../07-paws/admin-templates/configure-paw-at-internet-explorer-retirement.md)).*
* **Operating Systems**: Windows 10 Enterprise/Professional (all supported builds), Windows 11 Enterprise/Pro, Windows Server 2016, 2019, 2022, and 2025.

---

## Implementation Details
* **Priority**: High
* **GPO Paths / Registry Locations**:
  * **Disable Internet Explorer 11 as a Standalone Browser**:
    * GPO Path: `Computer Configuration\Policies\Administrative Templates\Windows Components\Internet Explorer\Disable Internet Explorer 11 as a standalone browser` -> **Enabled** (Select: `Always`)
    * Registry Path: `HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Main`
    * Value Name: `NotifyDisableIEOptions`
    * Value Type: `REG_DWORD`
    * Value Data: `0` (Always disabled / Never prompt user)
  * **Prevent Downloading of Enclosures in Web Feeds**:
    * GPO Path: `Computer Configuration\Policies\Administrative Templates\Windows Components\Internet Explorer\Feeds\Prevent downloading of enclosures` -> **Enabled**
    * Registry Path: `HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds`
    * Value Name: `DisableEnclosureDownload`
    * Value Type: `REG_DWORD`
    * Value Data: `1` (Enabled / Block enclosure downloads)
  * **Disable Cleartext Basic Feed Authentication over HTTP**:
    * GPO Path: `Computer Configuration\Policies\Administrative Templates\Windows Components\Internet Explorer\Feeds\Turn on Basic feed authentication over HTTP` -> **Disabled**
    * Registry Path: `HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds`
    * Value Name: `AllowBasicAuthInClear`
    * Value Type: `REG_DWORD`
    * Value Data: `0` (Disabled / Prohibit cleartext basic auth)

---

## Rationale
Internet Explorer 11 reached official end-of-life and retirement on modern Windows platforms. The standalone browser executable (`iexplore.exe`) lacks contemporary exploit mitigations, process sandboxing, and memory safety defenses, making it a persistent vector for zero-day exploitation and drive-by malware execution.

### 1. Standalone IE11 Retirement and Mandatory Redirection to Microsoft Edge
The standalone Internet Explorer architecture is fundamentally obsolete:
* **Exploitation of Obsolete Rendering Engines**: The MSHTML (`mshtml.dll`) and legacy scripting engines (JScript/VBScript) contain historical memory corruption vulnerabilities (such as use-after-free, out-of-bounds read/write, and type confusion). Threat actors frequently utilize crafted web pages, HTML attachments, or Microsoft Office documents embedding MSHTML objects (e.g., CVE-2021-40444, CVE-2024-38112) to force the launch of `iexplore.exe` and execute arbitrary shellcode outside modern browser sandboxes.
* **Lack of Modern Isolation**: Unlike Chromium-based Microsoft Edge, standalone IE11 does not feature per-tab site isolation, Arbitrary Code Guard (ACG), or modern Control Flow Guard (CFG) enhancements.
* Setting `NotifyDisableIEOptions = 0` (GPO: **Enabled: Always**) permanently disables `iexplore.exe`. Any attempt to launch Internet Explorer by users, protocol links, or background scripts is silently intercepted and redirected into Microsoft Edge.

### 2. Eliminating RSS/Atom Web Feed Exploitation Vectors
The Windows Web Feeds subsystem (`msfeeds.dll`) operates background synchronization for syndicated content:
* **Automated Payload Staging via Enclosures**: RSS feeds support "enclosures" (multimedia or binary attachments). In unhardened configurations, the feed engine can automatically download attached files in the background without user interaction, providing an automated ingress vector for malicious payloads. Setting `DisableEnclosureDownload = 1` forbids the downloading of file enclosures.
* **Credential Sniffing over Cleartext HTTP**: Transmitting HTTP Basic authentication headers over unencrypted HTTP channels allows network adversaries on the same LAN segment to capture cleartext usernames and passwords. Setting `AllowBasicAuthInClear = 0` strictly prohibits cleartext credential transmission in feed synchronization requests.

### 3. MITRE ATT&CK Mapping
* **T1189 - Drive-by Compromise**: Exploiting legacy browser engine vulnerabilities through web visits.
* **T1204.001 - User Execution: Malicious Link**: Directing users to malicious URLs that target retired browser components.
* **T1105 - Ingress Tool Transfer**: Automated background staging of malicious binaries via RSS feed enclosures.
* **T1557 - Adversary-in-the-Middle**: Intercepting cleartext HTTP Basic credentials transmitted by the feeds subsystem.

---

## Legacy Impact & Compatibility
* **Enterprise Mode Site List (IE Mode)**: Legacy intranet websites, legacy Java/ActiveX applications, and internal portals that strictly require the MSHTML rendering engine must be configured via **Microsoft Edge Enterprise Mode Site List**. In IE Mode, legacy pages render within a secure, multi-process Edge container, ensuring backward compatibility while keeping standalone `iexplore.exe` disabled.
* **Browser Redirection**: When users attempt to launch Internet Explorer from the Start menu or desktop shortcuts, Microsoft Edge will automatically launch with a banner explaining the transition.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to workstations and member servers (e.g., `GPO_Hardening_Endpoints`).
3. Configure the following policies:

* Navigate to: `Computer Configuration\Policies\Administrative Templates\Windows Components\Internet Explorer`
  * **Disable Internet Explorer 11 as a standalone browser**: Set to `Enabled`
  * Select drop-down value: `Always`
* Navigate to: `Computer Configuration\Policies\Administrative Templates\Windows Components\Internet Explorer\Feeds`
  * **Prevent downloading of enclosures**: Set to `Enabled`
* Navigate to: `Computer Configuration\Policies\Administrative Templates\Windows Components\Internet Explorer\Feeds`
  * **Turn on Basic feed authentication over HTTP**: Set to `Disabled`

4. Link the GPO to the appropriate Organizational Unit and verify policy enforcement using `gpupdate /force`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to configure the administrative template registry values:

[Download Script: Configure-EndAtInternetExplorerRetirement.ps1](../implementation_scripts/Configure-EndAtInternetExplorerRetirement.ps1)

```powershell
#Configure-EndAtInternetExplorerRetirement.ps1
# Description: Configures Administrative Templates: Internet Explorer 11 and Web Feeds Retirement Controls.

Write-Host "Configuring Administrative Templates: Internet Explorer 11 and Web Feeds Retirement Controls..." -ForegroundColor Cyan

if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" -Name "NotifyDisableIEOptions" -Value 0 -Type DWord -Force

if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds" -Name "DisableEnclosureDownload" -Value 1 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds" -Name "AllowBasicAuthInClear" -Value 0 -Type DWord -Force

Write-Host "[+] Administrative Templates: Internet Explorer 11 and Web Feeds Retirement Controls applied successfully." -ForegroundColor Green
```

*To verify the configuration:*

[Download Script: Get-EndAtInternetExplorerRetirementStatus.ps1](../audit_scripts/Get-EndAtInternetExplorerRetirementStatus.ps1)

```powershell
#Get-EndAtInternetExplorerRetirementStatus.ps1
# Description: Audits Administrative Templates: Internet Explorer 11 and Web Feeds Retirement Controls.

Write-Host "--- Auditing Administrative Templates: Internet Explorer 11 and Web Feeds Retirement Controls ---" -ForegroundColor Cyan
$script:Vulnerable = $false

$TargetKey = "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main"
$ValueName = "NotifyDisableIEOptions"
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

$TargetKey = "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds"
$ValueName = "DisableEnclosureDownload"
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

$TargetKey = "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds"
$ValueName = "AllowBasicAuthInClear"
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
* **CIS Benchmark**: CIS Microsoft Windows 10 Enterprise Benchmark: Section 18.10.45.1, Section 18.10.45.2, Section 18.10.45.3; CIS Microsoft Windows 11 Enterprise Benchmark: Section 18.10.45.1, Section 18.10.45.2, Section 18.10.45.3
* **DISA STIG**: Windows 10 STIG Rule WN10-CC-000380, Windows 11 STIG Rule WN11-CC-000380
* **Microsoft Lifecycle Guidance**: Internet Explorer 11 Desktop Application Retirement FAQ
* **ANSSI Active Directory Hardening Guide**: Section 3.3 (Web browser hardening and decommissioning obsolete runtimes)
