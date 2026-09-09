# [REQ-PAW-191] Administrative Templates: Internet Explorer 11 and Web Feeds Retirement Controls for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration. *(For Tier 2 Client Workstations and Member Servers, refer to baseline [REQ-END-202](../../08-endpoints/admin-templates/configure-end-at-internet-explorer-retirement.md)).*
* **Operating Systems**: Windows 10 Enterprise (1607+) and Windows 11 Enterprise.

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
Privileged Access Workstations (PAWs) are hardened environments dedicated to Tier 0 infrastructure management. General web browsing on a PAW is strictly prohibited by design. However, legacy operating system binaries and background feed engines remain embedded in the Windows platform, requiring absolute administrative disabling to prevent exploitation.

### 1. Eliminating Standalone IE11 and MSHTML Exploitation Surfaces
Internet Explorer 11 is retired and contains obsolete memory management logic:
* Standalone `iexplore.exe` lacks modern sandbox isolation and exploit mitigations. Adversaries targeting privileged administrators with targeted malicious documents or URI links can invoke legacy MSHTML rendering routines to achieve code execution on the management host.
* Setting `NotifyDisableIEOptions = 0` (GPO: **Enabled: Always**) permanently shuts down the standalone IE11 executable, automatically redirecting any accidental or programmatic invocation to modern Microsoft Edge.

### 2. Disabling Web Feed Staging and Cleartext Authentication
The Windows Feeds subsystem provides background content aggregation services that must be restricted:
* **Background Attachment Ingress**: Web feeds supporting enclosure downloads can be abused by adversaries to silently stage malicious binaries onto disk without triggering browser download warnings. Disabling `DisableEnclosureDownload` prevents the feeds engine from downloading binary attachments.
* **Prohibiting Unencrypted Feed Credentials**: Transmitting HTTP Basic credentials in cleartext exposes administrative accounts to network interception. Disabling `AllowBasicAuthInClear` ensures cleartext authentication is strictly rejected.

### 3. MITRE ATT&CK Mapping
* **T1189 - Drive-by Compromise**: Exploitation of legacy browser engine vulnerabilities.
* **T1204.001 - User Execution: Malicious Link**: Directing users to malicious URLs targeting retired browser components.
* **T1105 - Ingress Tool Transfer**: Automated staging of malicious binaries via RSS feed enclosures.
* **T1557 - Adversary-in-the-Middle**: Intercepting cleartext credentials transmitted across management segments.

---

## Legacy Impact & Compatibility
* **Operational Impact**: None. PAWs are dedicated to directory administration and never require standalone Internet Explorer or web feed subscriptions.
* **Administrative Management**: Administrative consoles requiring web-based interfaces (such as Azure Portal, Microsoft Entra ID admin center, or modern management appliances) are accessed via hardened modern browsers (Microsoft Edge with AppLocker/WDAC restrictions).

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to the PAWs Organizational Unit (e.g., `GPO_Hardening_PAW`).
3. Configure the following policies:

* Navigate to: `Computer Configuration\Policies\Administrative Templates\Windows Components\Internet Explorer`
  * **Disable Internet Explorer 11 as a standalone browser**: Set to `Enabled`
  * Select drop-down value: `Always`
* Navigate to: `Computer Configuration\Policies\Administrative Templates\Windows Components\Internet Explorer\Feeds`
  * **Prevent downloading of enclosures**: Set to `Enabled`
* Navigate to: `Computer Configuration\Policies\Administrative Templates\Windows Components\Internet Explorer\Feeds`
  * **Turn on Basic feed authentication over HTTP**: Set to `Disabled`

4. Link the GPO to the PAW Organizational Unit and enforce policy replication using `gpupdate /force`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to configure the administrative template registry values:

[Download Script: Configure-PawAtInternetExplorerRetirement.ps1](../implementation_scripts/Configure-PawAtInternetExplorerRetirement.ps1)

```powershell
#Configure-PawAtInternetExplorerRetirement.ps1
# Description: Configures Administrative Templates: Internet Explorer 11 and Web Feeds Retirement Controls for PAWs.

Write-Host "Configuring Administrative Templates: Internet Explorer 11 and Web Feeds Retirement Controls for PAWs..." -ForegroundColor Cyan

if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" -Name "NotifyDisableIEOptions" -Value 0 -Type DWord -Force

if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds" -Name "DisableEnclosureDownload" -Value 1 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds" -Name "AllowBasicAuthInClear" -Value 0 -Type DWord -Force

Write-Host "[+] Administrative Templates: Internet Explorer 11 and Web Feeds Retirement Controls for PAWs applied successfully." -ForegroundColor Green
```

*To verify the configuration:*

[Download Script: Get-PawAtInternetExplorerRetirementStatus.ps1](../audit_scripts/Get-PawAtInternetExplorerRetirementStatus.ps1)

```powershell
#Get-PawAtInternetExplorerRetirementStatus.ps1
# Description: Audits Administrative Templates: Internet Explorer 11 and Web Feeds Retirement Controls for PAWs.

Write-Host "--- Auditing Administrative Templates: Internet Explorer 11 and Web Feeds Retirement Controls for PAWs ---" -ForegroundColor Cyan
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
* **Microsoft Privileged Access Workstation Guidance**: PAW Software and Browser Attack Surface Reduction Rules
