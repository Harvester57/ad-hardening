# [REQ-END-130] User Profile: Shell RunAs User Suppression

## Target Scope
* **Applicable Systems**: Tier 2 Client Workstations and Member Servers. *(For Tier 0 Privileged Access Workstations, refer to tightened baseline [REQ-PAW-119](../../07-paws/user-profile/configure-up-runas-suppression.md)).*
* **Operating Systems**: Windows 10 Enterprise/Professional (all supported builds), Windows 11 Enterprise/Pro, Windows Server 2016, 2019, 2022, and 2025.

---

## Implementation Details
* **Priority**: Medium
* **GPO Paths / Registry Locations**:
  * **Shell RunAs User Context Menu Suppression**:
    * GPO Path: Group Policy Preferences Registry Policy
    * Registry Path: `HKLM\SOFTWARE\Classes\batfile\shell\runasuser`
      * Value Name: `SuppressionPolicy` | Value Type: `REG_DWORD` | Value Data: `4096` (0x00001000)
    * Registry Path: `HKLM\SOFTWARE\Classes\cmdfile\shell\runasuser`
      * Value Name: `SuppressionPolicy` | Value Type: `REG_DWORD` | Value Data: `4096` (0x00001000)
    * Registry Path: `HKLM\SOFTWARE\Classes\exefile\shell\runasuser`
      * Value Name: `SuppressionPolicy` | Value Type: `REG_DWORD` | Value Data: `4096` (0x00001000)
    * Registry Path: `HKLM\SOFTWARE\Classes\mscfile\shell\runasuser`
      * Value Name: `SuppressionPolicy` | Value Type: `REG_DWORD` | Value Data: `4096` (0x00001000)

---

## Rationale
In default Windows configurations, holding the Shift key while right-clicking an executable (`.exe`), command file (`.cmd`), batch script (`.bat`), or Microsoft Management Console file (`.msc`) exposes the "Run as different user" shell context menu command verb (`runasuser`). This feature encourages an anti-pattern that directly violates enterprise credential hygiene and exposes high-privilege credentials to theft on standard workstations.

### 1. Shell Context Menu Architecture & SuppressionPolicy
The Windows Explorer shell parses file association classes in `HKLM\SOFTWARE\Classes`:
* Each file type registers execution verbs (such as `open`, `runas`, and `runasuser`).
* When `runasuser` is triggered, Explorer invokes the Windows Credential UI (`credui.dll`), presenting an interactive prompt asking for an alternate username and password, which is then submitted to the Secondary Logon service.
* Setting `SuppressionPolicy = 4096` (`0x00001000`) instructs the Windows Shell verb evaluation engine to suppress the `runasuser` verb across all primary executable file classes (`exefile`, `batfile`, `cmdfile`, `mscfile`), removing the command from Explorer menus.

### 2. Threat Vectors & Credential Exposure Risks
* **Exposing Administrative Credentials on Tier 2 Workstations**: Administrators logged into standard workstations frequently use "Run as different user" to launch RSAT, ADUC (`dsa.msc`), or administrative scripts. This loads privileged Kerberos Ticket Granting Tickets (TGTs) and NTLM credentials into the local workstation's LSASS memory space, where an unprivileged adversary with local access or EDR bypass malware can scrape them.
* **Credential Harvesting & UI Spoofing**: Attackers can spoof or coerce interactive RunAs credential dialogs to phish administrative passwords from support personnel assisting users.
* **Enforcing Tiered Administration**: Suppressing `runasuser` eliminates the visual incentive for administrators to cross security boundaries from standard user desktops, enforcing the architectural requirement to perform privileged tasks exclusively from dedicated PAWs or managed jump hosts.

### 3. MITRE ATT&CK Mapping
* **T1056.002 - Input Capture: GUI Input Capture**: Spoofing or capturing credentials entered into interactive RunAs prompts.
* **T1548 - Abuse Elevation Control Mechanism**: Utilizing alternate user execution to bypass workstation role limitations.
* **T1003.001 - OS Credential Dumping: LSASS Memory**: Scraping administrative credentials loaded onto standard workstations via RunAs.

---

## Legacy Impact & Compatibility
* **Standard User Operations**: Standard desktop users never legitimately need to execute binaries as alternate domain users. Daily productivity tools, web browsers, and Line-of-Business software operate normally.
* **IT Support Workflows**: Helpdesk and desktop support personnel who historically used "Run as different user" to troubleshoot user workstations must transition to approved remote administration tools (such as Remote PowerShell, Microsoft Intune Remote Help, or dedicated administrative sessions).

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to workstations and member servers (e.g., `GPO_Hardening_Endpoints`).
3. Navigate to: `Computer Configuration \ Preferences \ Windows Settings \ Registry`
4. Create four Registry Items with the following parameters:
   * **Action**: `Update`
   * **Hive**: `HKEY_LOCAL_MACHINE`
   * **Value Name**: `SuppressionPolicy`
   * **Value Type**: `REG_DWORD`
   * **Value Data**: `4096`
   * **Key Paths**:
     * `SOFTWARE\Classes\batfile\shell\runasuser`
     * `SOFTWARE\Classes\cmdfile\shell\runasuser`
     * `SOFTWARE\Classes\exefile\shell\runasuser`
     * `SOFTWARE\Classes\mscfile\shell\runasuser`
5. Link the GPO to the appropriate Organizational Unit and verify policy enforcement using `gpupdate /force`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to configure Shell RunAs User suppression:

[Download Script: Configure-Uprunassuppression.ps1](../implementation_scripts/Configure-Uprunassuppression.ps1)

```powershell
# Configure-Uprunassuppression.ps1
Write-Host "Applying User Profile restriction: runas-suppression..." -ForegroundColor Cyan

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
Set-RegValue "HKLM:" "SOFTWARE\Classes\batfile\shell\runasuser" "SuppressionPolicy" "4096" "DWord"
Set-RegValue "HKLM:" "SOFTWARE\Classes\cmdfile\shell\runasuser" "SuppressionPolicy" "4096" "DWord"
Set-RegValue "HKLM:" "SOFTWARE\Classes\exefile\shell\runasuser" "SuppressionPolicy" "4096" "DWord"
Set-RegValue "HKLM:" "SOFTWARE\Classes\mscfile\shell\runasuser" "SuppressionPolicy" "4096" "DWord"

```

*To audit the hardening status:*

[Download Script: Get-UprunassuppressionStatus.ps1](../audit_scripts/Get-UprunassuppressionStatus.ps1)

```powershell
# Get-UprunassuppressionStatus.ps1
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
Test-RegValue "HKLM:" "SOFTWARE\Classes\batfile\shell\runasuser" "SuppressionPolicy" "4096"
Test-RegValue "HKLM:" "SOFTWARE\Classes\cmdfile\shell\runasuser" "SuppressionPolicy" "4096"
Test-RegValue "HKLM:" "SOFTWARE\Classes\exefile\shell\runasuser" "SuppressionPolicy" "4096"
Test-RegValue "HKLM:" "SOFTWARE\Classes\mscfile\shell\runasuser" "SuppressionPolicy" "4096"

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
* **CIS Benchmark**: CIS Microsoft Windows 10 Enterprise Benchmark: Section 18.9.x; CIS Microsoft Windows 11 Enterprise Benchmark: Section 18.9.x
* **DISA STIG**: Windows 10 STIG Rule WN10-CC-000130, Windows 11 STIG Rule WN11-CC-000130
* **ANSSI Active Directory Hardening Guide**: Recommendation R37 (Preventing credential leakage on client workstations)
* **Microsoft Privileged Access Strategy**: Enterprise Access Model: Credential Protection and Clean Source Architecture
