# [REQ-END-135] User Profile: Internet Explorer Options and Feeds Restrictions

## Target Scope
* **Applicable Systems**: Tier 2 Client Workstations and Member Servers. *(For Tier 0 Privileged Access Workstations, refer to reciprocal baseline [REQ-PAW-124](../../07-paws/user-profile/configure-up-ie-security.md)).*
* **Operating Systems**: Windows 10 Enterprise/Professional (all supported builds), Windows 11 Enterprise/Pro, Windows Server 2016, 2019, 2022, and 2025.

---

## Implementation Details
* **Priority**: Medium
* **GPO Paths / Registry Locations**:
  * **Disable Standalone Internet Explorer 11**:
    * GPO Path: `Computer Configuration\Administrative Templates\Windows Components\Internet Explorer\Disable Internet Explorer 11 as a standalone browser` -> Set to **Enabled**, configured to **Always**
  * **Prevent Downloading of Enclosures in RSS Feeds**:
    * GPO Path: `Computer Configuration\Administrative Templates\Windows Components\RSS Feeds\Prevent downloading of enclosures` -> Set to **Enabled**
    * Registry Path: `HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds`
    * Value Name: `DisableEnclosureDownload`
    * Value Type: `REG_DWORD`
    * Value Data: `1` (Block automatic downloading of feed enclosures and attachments)
  * **Disable Basic Feed Authentication over HTTP**:
    * GPO Path: `Computer Configuration\Administrative Templates\Windows Components\RSS Feeds\Turn on Basic feed authentication over HTTP` -> Set to **Disabled**
    * Registry Path: `HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds`
    * Value Name: `AllowBasicAuthInClear`
    * Value Type: `REG_DWORD`
    * Value Data: `0` (Disallow transmission of cleartext HTTP Basic credentials)
  * **Suppress IE Options Notification**:
    * Registry Path: `HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Main`
    * Value Name: `NotifyDisableIEOptions`
    * Value Type: `REG_DWORD`
    * Value Data: `0` (Suppress override notifications when IE options are locked)

---

## Rationale
Although modern versions of Windows 10 and Windows 11 have retired the standalone Internet Explorer 11 browser in favor of Microsoft Edge (Chromium), core legacy components of the Trident engine (`mshtml.dll`), the Windows Internet API (`wininet.dll`), URLMon, and the **Windows RSS Platform** (`msfeeds.dll`, `msfeedssync.exe`) remain deeply embedded in the operating system. These legacy subsystems are maintained for backward compatibility with legacy COM automation, WebBrowser controls, and internal enterprise tools.

Because these legacy components remain active in the background, they represent a persistent attack surface if left unconfigured.

### 1. Threat Vector: Automated Feed Enclosure Weaponization
RSS and Atom feed specifications support "enclosures"—references to external files (such as multimedia files, archives, or executable binaries) linked within an XML feed item:
* When feed enclosure downloading is permitted, the Windows Feed Synchronizer (`msfeedssync.exe`) or any process consuming feeds through `msfeeds.dll` automatically contacts external servers, downloads the enclosed files, and writes them into local user cache directories without explicit user interaction or warning prompts.
* Threat actors have weaponized RSS enclosures as an out-of-band delivery mechanism for malware staging, living-off-the-land persistence, and command-and-control (C2) instruction retrieval (MITRE T1566.002 - Spearphishing Link, T1105 - Ingress Tool Transfer).
* Enforcing `DisableEnclosureDownload = 1` prohibits the Windows RSS Platform from automatically fetching and storing enclosures, eliminating this automated file ingress vector.

### 2. Threat Vector: Cleartext HTTP Basic Authentication Exposure
Feeds hosted on internal or external web servers may request user authentication:
* When "Basic feed authentication over HTTP" is permitted, the feed engine can send authentication headers using HTTP Basic Authentication (`Authorization: Basic <base64>`) over unencrypted HTTP (TCP port 80).
* HTTP Basic Authentication transmits credentials in base64 format without cryptographic encryption. An adversary situated on the local network (via Wi-Fi eavesdropping, ARP poisoning, DNS spoofing, or compromised network infrastructure) can capture the plaintext username and password.
* Setting `AllowBasicAuthInClear = 0` enforces that credentials are never transmitted over unencrypted HTTP channels, requiring TLS encryption for any authenticated feed transactions.

### 3. Decommissioning IE11 & Locking Security Zones
* Disabling Internet Explorer 11 as a standalone browser ensures that users are redirected to modern, sandboxed browsers (such as Microsoft Edge) that feature hardware-isolated browsing, Application Guard, and robust exploit mitigations.
* Suppressing IE options notifications and locking down legacy Internet Control Panel settings (`inetcpl.cpl`) prevents users or malicious scripts from lowering legacy zone security restrictions (e.g., Trusted Sites or Intranet zones).

### 4. MITRE ATT&CK Mapping
* **T1566.002 - Phishing: Spearphishing Link**: Mitigating untrusted content and feed links.
* **T1105 - Ingress Tool Transfer**: Preventing automated retrieval and local staging of binary files via RSS enclosures.
* **T1557 - Adversary-in-the-Middle**: Eliminating cleartext credential exposure over unencrypted HTTP feed channels.
* **T1204.001 - User Execution: Malicious Link**: Redirecting legacy web interaction to modern protected browsers.

---

## Legacy Impact & Compatibility
* **Standard Web Browsing**: Enterprise users utilize Microsoft Edge or approved third-party browsers; modern web usage is completely unaffected.
* **IE Mode in Edge**: Line-of-business applications requiring Internet Explorer compatibility can still utilize Microsoft Edge IE Mode under centralized Enterprise Mode Site Lists (`EMIESiteList`) without enabling insecure legacy enclosure or cleartext authentication behaviors.
* **RSS Reader Utilities**: Standard enterprise workflows rarely rely on legacy Windows native RSS sync; dedicated RSS applications manage their own secure transport connections over HTTPS.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to workstations and member servers (e.g., `GPO_Hardening_Endpoints`).
3. Navigate to: `Computer Configuration \ Administrative Templates \ Windows Components \ Internet Explorer`
   * Double-click **Disable Internet Explorer 11 as a standalone browser** -> Set to **Enabled**, and select **Always**.
4. Navigate to: `Computer Configuration \ Administrative Templates \ Windows Components \ RSS Feeds`
   * Double-click **Prevent downloading of enclosures** -> Set to **Enabled**.
   * Double-click **Turn on Basic feed authentication over HTTP** -> Set to **Disabled**.
5. Link the GPO to the target Organizational Unit and enforce policy application with `gpupdate /force`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to configure Internet Explorer and RSS feed security restrictions:

[Download Script: Configure-Upiesecurity.ps1](../implementation_scripts/Configure-Upiesecurity.ps1)

```powershell
# Configure-Upiesecurity.ps1
Write-Host "Applying User Profile restriction: ie-security..." -ForegroundColor Cyan

function Set-RegValue {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [string]$hive,
        [string]$keyPath,
        [string]$name,
        [string]$value,
        [string]$type
    )
    if ($PSCmdlet.ShouldProcess("$hive\$keyPath", "Set registry value $name to $value")) {
        $fullPath = "$hive\$keyPath"
        $parent = Split-Path -Path $fullPath
        if (-not (Test-Path $parent)) { New-Item -Path $parent -Force | Out-Null }
        if (-not (Test-Path $fullPath)) { New-Item -Path $fullPath -Force | Out-Null }
        Set-ItemProperty -Path $fullPath -Name $name -Value $value -Type $type -Force
    }
}
Set-RegValue "HKLM:" "SOFTWARE\Policies\Microsoft\Internet Explorer\Main" "NotifyDisableIEOptions" "0" "DWord"
Set-RegValue "HKLM:" "SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds" "DisableEnclosureDownload" "1" "DWord"
Set-RegValue "HKLM:" "SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds" "AllowBasicAuthInClear" "0" "DWord"

```

*To audit the hardening status:*

[Download Script: Get-UpiesecurityStatus.ps1](../audit_scripts/Get-UpiesecurityStatus.ps1)

```powershell
# Get-UpiesecurityStatus.ps1
$script:Vulnerable = $false

function Test-RegValue {
    param (
        [string]$hive,
        [string]$keyPath,
        [string]$name,
        [string]$expected
    )
    $fullPath = "$hive\$keyPath"
    $val = Get-ItemProperty -Path $fullPath -Name $name -ErrorAction SilentlyContinue
    $actual = if ($val) { $val.$name } else { "" }
    if ($actual -ne $expected) {
        $script:Vulnerable = $true
    }
}
Test-RegValue "HKLM:" "SOFTWARE\Policies\Microsoft\Internet Explorer\Main" "NotifyDisableIEOptions" "0"
Test-RegValue "HKLM:" "SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds" "DisableEnclosureDownload" "1"
Test-RegValue "HKLM:" "SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds" "AllowBasicAuthInClear" "0"

if ($script:Vulnerable) {
    Write-Output "Non-Compliant"
    exit 1
} else {
    Write-Output "Compliant"
    exit 0
}
```

---

## Sources & Compliance References
* **CIS Microsoft Windows 10 Enterprise Benchmark**: Section 18.9.36.1 (L1 - Ensure 'Disable Internet Explorer 11 as a standalone browser' is set to 'Enabled'); Section 18.9.52.1 (L1 - Ensure 'Prevent downloading of enclosures' is set to 'Enabled'); Section 18.9.52.2 (L1 - Ensure 'Turn on Basic feed authentication over HTTP' is set to 'Disabled')
* **CIS Microsoft Windows 11 Enterprise Benchmark**: Section 18.9.36.1; Section 18.9.52.1; Section 18.9.52.2
* **DISA STIG**: Windows 10 STIG Rule WN10-CC-000210, WN10-CC-000215; Windows 11 STIG Rule WN11-CC-000210, WN11-CC-000215
* **ANSSI Active Directory Hardening Guide**: Client Workstation Security Baselines and Web Browser Lockdown
* **Microsoft Lifecycle & Security Guidance**: Internet Explorer 11 Desktop App Retirement FAQ and Edge IE Mode Architecture
