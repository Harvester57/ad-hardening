# [REQ-PAW-124] User Profile: Internet Explorer Options and Feeds Restrictions for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration. *(For Tier 2 Client Workstations and Member Servers, refer to reciprocal baseline [REQ-END-135](../../08-endpoints/user-profile/configure-up-ie-security.md)).*
* **Operating Systems**: Windows 10 Enterprise (1607+) and Windows 11 Enterprise.

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
Privileged Access Workstations (PAWs) are dedicated exclusively to high-privilege administrative tasks, such as managing Active Directory Domain Services, Azure AD Connect, PKI infrastructure, and Domain Controllers. Standard user activities—including general web browsing, personal email, and social media—are strictly forbidden on PAWs by foundational Tier 0 isolation principles.

Even when direct interactive browsing is prohibited, background operating system components associated with legacy Internet Explorer, WinINet, and the Windows RSS Platform (`msfeeds.dll`, `msfeedssync.exe`) remain installed on Windows clients. Hardening these legacy components is essential to prevent background exploitation vectors on Tier 0 consoles.

### 1. Eliminating Background Enclosure Ingress on Tier 0 Bastions
The Windows RSS platform supports automated enclosure downloads—retrieving binary attachments embedded within XML feeds:
* In a compromised or unhardened configuration, any process or background task triggering feed synchronization (`msfeedssync.exe`) could contact external or untrusted servers and automatically download arbitrary files directly onto the PAW filesystem.
* Attackers have historically utilized RSS enclosures as an automated staging vector for malicious executables, DLLs, and scripts (MITRE T1566.002, T1105).
* On a PAW holding Tier 0 domain credentials, automated file download mechanisms represent an intolerable supply chain and payload delivery risk. Setting `DisableEnclosureDownload = 1` permanently disables automatic enclosure fetching.

### 2. Preventing Cleartext Administrative Credential Exposure
If an administrative utility or feed reader attempts to authenticate against an intranet or external endpoint:
* Allowing Basic feed authentication over HTTP permits the transmission of `Authorization: Basic` headers containing unencrypted base64-encoded credentials over plaintext TCP port 80.
* If an administrator inadvertently enters Tier 0 credentials or if an automated task executes under a privileged service account, an attacker conducting network sniffing (Adversary-in-the-Middle / ARP spoofing) within the subnet could capture the plaintext password.
* Setting `AllowBasicAuthInClear = 0` guarantees that basic authentication is strictly rejected across unencrypted channels.

### 3. Decommissioning Standalone IE11 and Zone Lockdown
* Fully disabling standalone IE11 eliminates legacy browser launch vectors, preventing accidental interactive web browsing from privileged consoles.
* Enforcing `NotifyDisableIEOptions = 0` suppresses administrative override prompts, ensuring that legacy Internet Control Panel settings (`inetcpl.cpl`) cannot be altered locally.

### 4. MITRE ATT&CK Mapping
* **T1566.002 - Phishing: Spearphishing Link**: Restricting untrusted web and feed interactions on Tier 0 systems.
* **T1105 - Ingress Tool Transfer**: Preventing background file staging via RSS enclosures.
* **T1557 - Adversary-in-the-Middle**: Eliminating plaintext credential transmission over unencrypted HTTP channels.
* **T1204.001 - User Execution: Malicious Link**: Eliminating interactive legacy browser exposure on PAWs.

---

## Legacy Impact & Compatibility
* **Zero Disruption for Tier 0 Administration**: Administrative tools such as RSAT, PowerShell remoting, and Active Directory Administrative Center do not depend on standalone IE11 or RSS enclosure downloads.
* **Network Hygiene**: Eliminates background feed polling and unauthenticated HTTP requests originating from Tier 0 management subnets.
* **Total Alignment with PAW Baseline**: Reinforces the clean-source principle by ensuring that the operating system cannot be induced to fetch unvetted remote payloads in the background.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to the PAW Organizational Unit (e.g., `GPO_Hardening_PAWs`).
3. Navigate to: `Computer Configuration \ Administrative Templates \ Windows Components \ Internet Explorer`
   * Double-click **Disable Internet Explorer 11 as a standalone browser** -> Set to **Enabled**, and select **Always**.
4. Navigate to: `Computer Configuration \ Administrative Templates \ Windows Components \ RSS Feeds`
   * Double-click **Prevent downloading of enclosures** -> Set to **Enabled**.
   * Double-click **Turn on Basic feed authentication over HTTP** -> Set to **Disabled**.
5. Link the GPO to the dedicated PAW Organizational Unit and enforce policy application with `gpupdate /force`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to configure Internet Explorer and RSS feed security restrictions on PAWs:

[Download Script: Configure-PawUpiesecurity.ps1](../implementation_scripts/Configure-PawUpiesecurity.ps1)

```powershell
# Configure-PawUpiesecurity.ps1
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

[Download Script: Get-PawUpiesecurityStatus.ps1](../audit_scripts/Get-PawUpiesecurityStatus.ps1)

```powershell
# Get-PawUpiesecurityStatus.ps1
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
* **ANSSI Active Directory Hardening Guide**: Workstation Baseline Guide and Eliminating Legacy Attack Surface on Tier 0 Assets
* **Microsoft Privileged Access Workstation (PAW) Guidance**: Internet Browsing Restrictions and Web Surface Minimization
