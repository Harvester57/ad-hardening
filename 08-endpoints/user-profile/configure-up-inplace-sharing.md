# [REQ-END-129] User Profile: In-Place Sharing Restrictions

## Target Scope
* **Applicable Systems**: Tier 2 Client Workstations and Member Servers. *(For Tier 0 Privileged Access Workstations, refer to tightened baseline [REQ-PAW-118](../../07-paws/user-profile/configure-up-inplace-sharing.md)).*
* **Operating Systems**: Windows 10 Enterprise/Professional (all supported builds), Windows 11 Enterprise/Pro, Windows Server 2016, 2019, 2022, and 2025.

---

## Implementation Details
* **Priority**: Medium
* **GPO Paths / Registry Locations**:
  * **Turn Off In-Place Sharing (User Configuration)**:
    * GPO Path: `User Configuration\Administrative Templates\Windows Components\File Explorer\Turn off in-place sharing` -> **Enabled**
    * Registry Path: `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`
    * Value Name: `NoInplaceSharing`
    * Value Type: `REG_DWORD`
    * Value Data: `1` (Enabled / Block in-place sharing flyout)
  * **Turn Off In-Place Sharing (Computer Configuration)**:
    * GPO Path: `Computer Configuration\Administrative Templates\Windows Components\File Explorer\Turn off in-place sharing` -> **Enabled**
    * Registry Path: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer`
    * Value Name: `NoInplaceSharing`
    * Value Type: `REG_DWORD`
    * Value Data: `1` (Enabled / Block in-place sharing flyout machine-wide)

---

## Rationale
In modern versions of Windows, File Explorer incorporates the "In-Place Sharing" framework (also known as the Share Flyout or Share Charm). This mechanism provides users with a persistent "Share" button on the Explorer ribbon and context menu, allowing files to be directly broadcasted or transmitted to third-party applications, personal email accounts, social media platforms, or nearby devices via Nearby Sharing (Bluetooth and Wi-Fi Direct).

### 1. File Explorer Sharing Architecture & DLP Bypass
The in-place sharing subsystem interfaces directly with the Windows Shell and modern Universal Windows Platform (UWP) share targets:
* When a user selects a file and clicks "Share", Explorer activates `ShellExperienceHost.exe` to display the modern sharing contract flyout.
* This interface presents sharing pathways—such as personal consumer cloud accounts, consumer messaging utilities, and Nearby Sharing—that operate independently of traditional enterprise mail clients or governed document repositories.
* Because in-place sharing bypasses traditional gateway Data Loss Prevention (DLP) proxies and email hygiene filters, users or insider threats can transmit sensitive enterprise files directly to unsanctioned external endpoints with minimal friction.

### 2. Threat Vectors & Accidental Exfiltration
* **Unauthorized Data Exfiltration**: Malicious insiders or compromised accounts can leverage the modern share contract to upload proprietary intellectual property or customer data to unapproved cloud storage or personal webmail.
* **Nearby Sharing Leaks**: Nearby Sharing utilizes peer-to-peer Wi-Fi Direct and Bluetooth beacons. Accidental clicks or automated prompts in public spaces (airports, conferences) can inadvertently broadcast corporate documents to nearby untrusted consumer laptops.
* Setting `NoInplaceSharing = 1` removes the "Share" button from the File Explorer toolbar, suppresses the share context menu entry, and shuts down the underlying sharing broker.

### 3. MITRE ATT&CK Mapping
* **T1048 - Exfiltration Over Alternative Protocol**: Bypassing perimeter DLP via peer-to-peer or modern app sharing protocols.
* **T1537 - Transfer Data to Cloud Account**: Uploading corporate documents to unmanaged personal cloud accounts via share flyouts.
* **T1052 - Exfiltration Over Physical Medium / Local Radio**: Exfiltrating data via Nearby Sharing (Bluetooth / Wi-Fi Direct).

---

## Legacy Impact & Compatibility
* **Governed Enterprise Collaboration**: Authorized enterprise sharing mechanisms—such as Microsoft SharePoint, OneDrive for Business synchronized folders, and corporate Outlook email—remain fully functional and adhere to organizational compliance boundaries.
* **User Workflow Cleanliness**: Eliminates accidental share prompts and cleans the File Explorer ribbon for enterprise users.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to workstations and member servers (e.g., `GPO_Hardening_Endpoints`).
3. Configure the following policies:

* Navigate to: `User Configuration \ Administrative Templates \ Windows Components \ File Explorer`
  * **Turn off in-place sharing**: Set to **Enabled**
* Navigate to: `Computer Configuration \ Administrative Templates \ Windows Components \ File Explorer`
  * **Turn off in-place sharing**: Set to **Enabled**

4. Link the GPO to the appropriate Organizational Unit and verify policy enforcement using `gpupdate /force`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to disable in-place sharing:

[Download Script: Configure-Upinplacesharing.ps1](../implementation_scripts/Configure-Upinplacesharing.ps1)

```powershell
# Configure-Upinplacesharing.ps1
Write-Host "Applying User Profile restriction: inplace-sharing..." -ForegroundColor Cyan

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
Set-RegValue "HKCU:" "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoInplaceSharing" "1" "DWord"
Set-RegValue "HKLM:" "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoInplaceSharing" "1" "DWord"

# Apply to Default User profile for new sessions
$DefaultHivePath = "C:\Users\Default\NTUSER.DAT"
if (Test-Path $DefaultHivePath) {
    reg load HKU\DefaultUser $DefaultHivePath | Out-Null
    $DefaultKey = "Registry::HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    if (-not (Test-Path $DefaultKey)) { New-Item -Path $DefaultKey -Force | Out-Null }
    Set-ItemProperty -Path $DefaultKey -Name "NoInplaceSharing" -Value "1" -Type DWord -Force
    [GC]::Collect()
    [GC]::WaitForPendingFinalizers()
    reg unload HKU\DefaultUser | Out-Null
}

```

*To audit the hardening status:*

[Download Script: Get-UpinplacesharingStatus.ps1](../audit_scripts/Get-UpinplacesharingStatus.ps1)

```powershell
# Get-UpinplacesharingStatus.ps1
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
Test-RegValue "HKCU:" "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoInplaceSharing" "1"

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
* **CIS Benchmark**: CIS Microsoft Windows 10 Enterprise Benchmark: Section 19.7.x (File Explorer); CIS Microsoft Windows 11 Enterprise Benchmark: Section 19.7.x
* **DISA STIG**: Windows 10 STIG Rule WN10-CC-000150, Windows 11 STIG Rule WN11-CC-000150
* **ANSSI Active Directory Hardening Guide**: Recommendation R37 (Securing workstation user profiles and preventing data exfiltration)
* **Microsoft Windows Shell Documentation**: Managing Modern Sharing Contracts and In-Place Sharing Policies
