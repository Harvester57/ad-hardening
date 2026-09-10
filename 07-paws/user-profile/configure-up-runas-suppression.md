# [REQ-PAW-119] User Profile: Shell RunAs User Suppression for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 Active Directory and identity infrastructure administration. *(For Tier 2 Client Workstations and Member Servers, refer to baseline [REQ-END-130](../../08-endpoints/user-profile/configure-up-runas-suppression.md)).*
* **Operating Systems**: Windows 10 Enterprise (version 1809 and above), Windows 11 Enterprise.

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
Privileged Access Workstations (PAWs) operate under strict dedicated role segregation. An administrator logging into a Tier 0 PAW authenticates directly with their Tier 0 privileged identity (e.g., Domain Admin smart card or FIDO2 key). The Windows Explorer "Run as different user" context menu verb (`runasuser`) invites multi-account usage patterns, credential confusion, and potential interactive credential theft.

### 1. Shell Verb Architecture & Context Menu Suppression
The Windows Explorer shell parses file association classes located in `HKLM\SOFTWARE\Classes`:
* For key executable and script extensions (`.exe`, `.bat`, `.cmd`, `.msc`), the shell registers context menu command verbs.
* When a user triggers `runasuser`, Explorer displays the Windows Credential UI dialog and passes credentials to the Secondary Logon service to instantiate a separate process token.
* By setting `SuppressionPolicy = 4096` (`0x00001000`) across `batfile`, `cmdfile`, `exefile`, and `mscfile` classes, the operating system completely suppresses and removes the "Run as different user" option from all shell context menus.

### 2. Tier 0 Architectural Purity & Credential Isolation
* **Enforcing Single-Tier Operational Discipline**: On a PAW, all management tools must execute directly within the authenticated Tier 0 logon session. Running applications under secondary, unvetted, or lower-tier credentials breaks administrative traceability and risks cross-tier contamination.
* **Neutralizing Credential Harvesting Interfaces**: Suppressing interactive RunAs dialogs terminates an interface that could be spoofed by malware or malicious scripts to prompt administrators for alternate administrative passwords.
* **Alignment with Secondary Logon Lockdown**: This control directly reinforces [REQ-PAW-128](configure-up-seclogon-service.md) (disabling `seclogon`), ensuring that disabled background services are not surfaced to users as broken context menu actions.

### 3. MITRE ATT&CK Mapping
* **T1056.002 - Input Capture: GUI Input Capture**: Preventing credential harvesting via spoofed RunAs dialogs.
* **T1548 - Abuse Elevation Control Mechanism**: Preventing unauthorized alternate user execution on dedicated administration consoles.
* **T1003.001 - OS Credential Dumping: LSASS Memory**: Terminating alternate credential injection into local workstation memory.

---

## Legacy Impact & Compatibility
* **PAW Dedicated Role**: PAW users perform administrative tasks under their primary logged-on Tier 0 account. The "Run as different user" verb is never required in standard PAW operations.
* **Zero Disruption**: Standard right-click "Run as administrator" (UAC elevation under the current user's administrative token) remains available and fully functional for elevated operations.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to Tier 0 Privileged Access Workstations (e.g., `GPO_Hardening_PAW`).
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
5. Link the GPO to the dedicated PAW Organizational Unit and enforce replication using `gpupdate /force`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to configure Shell RunAs User suppression on the PAW console:

[Download Script: Configure-PawUprunassuppression.ps1](../implementation_scripts/Configure-PawUprunassuppression.ps1)

```powershell
# Configure-PawUprunassuppression.ps1
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

[Download Script: Get-PawUprunassuppressionStatus.ps1](../audit_scripts/Get-PawUprunassuppressionStatus.ps1)

```powershell
# Get-PawUprunassuppressionStatus.ps1
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
* **ANSSI Active Directory Hardening Guide**: Recommendation R37 (Securing administrative workstations and preventing credential leakage)
* **Microsoft Privileged Access Guidance**: Clean Source Principle: PAW Administrative Architecture and Identity Hygiene
