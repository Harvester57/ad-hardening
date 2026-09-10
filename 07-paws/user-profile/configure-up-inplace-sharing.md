# [REQ-PAW-118] User Profile: In-Place Sharing Restrictions for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 Active Directory and identity infrastructure administration. *(For Tier 2 Client Workstations and Member Servers, refer to baseline [REQ-END-129](../../08-endpoints/user-profile/configure-up-inplace-sharing.md)).*
* **Operating Systems**: Windows 10 Enterprise (version 1809 and above), Windows 11 Enterprise.

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
Privileged Access Workstations (PAWs) are dedicated exclusively to directory administration, identity synchronization, and domain-level maintenance. Administrative sessions on PAWs interact with sensitive directory export files (`ntds.dit` snippets, LDIFDE exports, sensitive PowerShell scripts, and recovery key backups). Allowing interactive, peer-to-peer, or modern shell file sharing from a PAW shatters data containment and provides immediate exfiltration channels.

### 1. Shell Sharing Architecture & PAW Isolation
The Windows File Explorer "In-Place Sharing" framework integrates directly with modern Universal Windows Platform (UWP) apps and radio protocols:
* The Share Flyout exposes targets such as Nearby Sharing (which utilizes Bluetooth and Wi-Fi Direct) and consumer cloud storage connectors.
* On a Tier 0 PAW console, wireless radios (Bluetooth, Wi-Fi) and peer-to-peer file transfer protocols must be strictly suppressed.
* Permitting the in-place sharing UI on a PAW risks inadvertent data transfer of sensitive domain administration artifacts to nearby devices or untrusted applications.
* By enforcing `NoInplaceSharing = 1` across both user and computer policies, the operating system removes the "Share" button from the File Explorer interface and terminates the underlying sharing broker.

### 2. Tier 0 Data Containment & Perimeter Defense
* **Data Containment on Dedicated Consoles**: Files residing on a PAW must never be shared informally. Artifact transfers (e.g., audit logs, scripts) must proceed exclusively through approved, cryptographically authenticated, and monitored administrative channels (such as secure Jump hosts or central management repositories).
* **Eliminating Accidental Exfiltration Vectors**: Suppressing the Share flyout eliminates the risk that an operator accidentally broadcasts an export containing user accounts, group memberships, or LAPS passwords to nearby radios.
* **Streamlining Explorer for Administration**: Keeps the administrative user interface lean, focused, and free of extraneous consumer features.

### 3. MITRE ATT&CK Mapping
* **T1048 - Exfiltration Over Alternative Protocol**: Exfiltrating sensitive directory artifacts via peer-to-peer share protocols.
* **T1537 - Transfer Data to Cloud Account**: Uploading administrative exports to personal cloud accounts.
* **T1052 - Exfiltration Over Physical Medium / Local Radio**: Broadcasting administrative data via Nearby Sharing (Bluetooth / Wi-Fi Direct).

---

## Legacy Impact & Compatibility
* **PAW Dedicated Role**: PAWs do not participate in end-user file sharing, social collaboration, or consumer messaging.
* **Zero Operational Disruption**: Legitimate administrative operations, file transfers over secure SMBv3 administrative shares, and PowerShell script deployment operate without disruption.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to Tier 0 Privileged Access Workstations (e.g., `GPO_Hardening_PAW`).
3. Configure the following policies:

* Navigate to: `User Configuration \ Administrative Templates \ Windows Components \ File Explorer`
  * **Turn off in-place sharing**: Set to **Enabled**
* Navigate to: `Computer Configuration \ Administrative Templates \ Windows Components \ File Explorer`
  * **Turn off in-place sharing**: Set to **Enabled**

4. Link the GPO to the dedicated PAW Organizational Unit and enforce replication using `gpupdate /force`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to configure In-Place Sharing restrictions on the PAW console:

[Download Script: Configure-PawUpinplacesharing.ps1](../implementation_scripts/Configure-PawUpinplacesharing.ps1)

```powershell
# Configure-PawUpinplacesharing.ps1
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

[Download Script: Get-PawUpinplacesharingStatus.ps1](../audit_scripts/Get-PawUpinplacesharingStatus.ps1)

```powershell
# Get-PawUpinplacesharingStatus.ps1
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
* **CIS Benchmark**: CIS Microsoft Windows 10 Enterprise Benchmark: Section 19.7.x; CIS Microsoft Windows 11 Enterprise Benchmark: Section 19.7.x
* **DISA STIG**: Windows 10 STIG Rule WN10-CC-000150, Windows 11 STIG Rule WN11-CC-000150
* **ANSSI Active Directory Hardening Guide**: Recommendation R37 (Securing administrative workstations and data containment)
* **Microsoft Privileged Access Guidance**: Clean Source Principle: PAW Administrative Architecture and Data Isolation
