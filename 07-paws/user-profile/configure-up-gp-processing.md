# [REQ-PAW-121] User Profile: Group Policy Registry Policy Processing Behaviors for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration. *(For Tier 2 Client Workstations and Member Servers, refer to reciprocal baseline [REQ-END-132](../../08-endpoints/user-profile/configure-up-gp-processing.md)).*
* **Operating Systems**: Windows 10 Enterprise (1607+) and Windows 11 Enterprise.

---

## Implementation Details
* **Priority**: Medium
* **GPO Paths / Registry Locations**:
  * **Configure Registry Policy Processing**:
    * GPO Path: `Computer Configuration\Administrative Templates\System\Group Policy\Configure Registry policy processing` -> Set to **Enabled**
      * Check **Process even if the Group Policy objects have not changed** (`NoGPOListChanges` = `0`)
      * Uncheck **Do not apply during periodic background processing** (`NoBackgroundPolicy` = `0`)
    * Registry Path: `HKLM\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}`
    * Value Name: `NoBackgroundPolicy`
    * Value Type: `REG_DWORD`
    * Value Data: `0` (Allow policy application during periodic background refreshes)
    * Value Name: `NoGPOListChanges`
    * Value Type: `REG_DWORD`
    * Value Data: `0` (Reapply policy settings even if the GPO list has not changed in Active Directory)

---

## Rationale
Privileged Access Workstations (PAWs) enforce the most stringent security configurations across the enterprise to safeguard Tier 0 identity assets. Group Policy client configuration is applied by specialized Client-Side Extensions (CSEs). The GUID `{35378EAC-683F-11D2-A89A-00C04FBBCFA2}` corresponds to the core **Registry Client-Side Extension** (`gptext.dll`), which reads and applies the administrative templates and security settings packaged within Group Policy Objects.

### 1. Group Policy Processing Optimization vs. PAW Drift Risk
By design, the Windows Group Policy engine (`gpsvc`) incorporates an optimization mechanism to conserve computing resources:
* Periodic background processing (occurring every 90 minutes with a randomized 0 to 30-minute jitter) checks if the version number of assigned GPOs has changed in Active Directory (`SYSVOL`).
* If no changes are detected, the Group Policy client **skips** processing the Registry CSE.
* On a PAW, where administrative users possess local administrative rights for operational troubleshooting, an administrator or automated script might modify registry values (e.g., temporarily enabling a debugging feature, altering proxy settings, modifying audit policies, or tweaking Windows Defender settings).
* If `NoGPOListChanges` is not configured, these drifted or tampered registry keys **will never revert** to the domain baseline during periodic background refreshes, leaving the PAW in a non-compliant or compromised posture until the GPO version increments in AD.

### 2. Continuous Enforcement & Self-Healing Baseline on PAWs
* **Automated Self-Healing**: Configuring `NoGPOListChanges = 0` forces the Registry CSE to re-read and enforce all registry settings defined in the GPO cache on every processing cycle, regardless of whether GPO files in `SYSVOL` have been modified. Any unauthorized or accidental registry changes on the PAW are automatically overwritten and corrected.
* **Background Application**: Setting `NoBackgroundPolicy = 0` ensures that registry policies are re-applied in the background during active administrative sessions, rather than delaying compliance enforcement until machine reboot or user logoff.
* **Impairing Defense Neutralization**: Attackers leveraging living-off-the-land techniques or malware attempting to weaken host defenses (e.g., turning off Tamper Protection, altering firewall exceptions, disabling logging) have their modifications systematically undone by the Group Policy engine.

### 3. MITRE ATT&CK Mapping
* **T1484.001 - Domain Policy Modification: Group Policy Modification**: Enforcing client-side policy persistence and continuous adherence to central domain controls.
* **T1562.001 - Impair Defenses: Disable or Modify Tools**: Neutralizing local defense impairment attempts by automatically restoring tampered registry configurations.
* **T1112 - Modify Registry**: Re-asserting authoritative security settings against local configuration drift.

---

## Legacy Impact & Compatibility
* **Zero Disruption for Dedicated PAWs**: Re-evaluating the local `registry.pol` cache requires negligible CPU and I/O resources, completing within milliseconds without interrupting running administrative tools.
* **Offline Resiliency**: If a PAW is operating in an isolated administrative management network without constant DC connectivity, the local policy engine continues to enforce the cached configuration.
* **Operational Predictability**: Guarantees that all PAWs remain in an identical, strictly audited state aligned with enterprise Tier 0 security mandates.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to the PAW Organizational Unit (e.g., `GPO_Hardening_PAWs`).
3. Navigate to: `Computer Configuration \ Administrative Templates \ System \ Group Policy`
4. Double-click **Configure Registry policy processing** and configure:
   * Select **Enabled**
   * Check **Process even if the Group Policy objects have not changed**
   * Ensure **Do not apply during periodic background processing** is **unchecked**
5. Link the GPO to the dedicated PAW Organizational Unit and enforce policy application using `gpupdate /force`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to configure the Registry CSE processing behaviors on PAWs:

[Download Script: Configure-PawUpgpprocessing.ps1](../implementation_scripts/Configure-PawUpgpprocessing.ps1)

```powershell
# Configure-PawUpgpprocessing.ps1
Write-Host "Applying User Profile restriction: gp-processing..." -ForegroundColor Cyan

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
Set-RegValue "HKLM:" "SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" "NoBackgroundPolicy" "0" "DWord"
Set-RegValue "HKLM:" "SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" "NoGPOListChanges" "0" "DWord"

```

*To audit the hardening status:*

[Download Script: Get-PawUpgpprocessingStatus.ps1](../audit_scripts/Get-PawUpgpprocessingStatus.ps1)

```powershell
# Get-PawUpgpprocessingStatus.ps1
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
Test-RegValue "HKLM:" "SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" "NoBackgroundPolicy" "0"
Test-RegValue "HKLM:" "SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" "NoGPOListChanges" "0"

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
* **CIS Microsoft Windows 10 Enterprise Benchmark**: Section 18.9.31.2 (L1 - Ensure 'Configure registry policy processing: Do not apply during periodic background processing' is set to 'Disabled')
* **CIS Microsoft Windows 11 Enterprise Benchmark**: Section 18.9.31.2 (L1 - Ensure 'Configure registry policy processing: Process even if the Group Policy objects have not changed' is set to 'Enabled: TRUE')
* **DISA STIG**: Windows 10 / 11 STIG Rule WN10-CC-000075 (Registry policy processing must be configured to process regardless of changes)
* **ANSSI Active Directory Hardening Guide**: Workstation Baseline Guide and Group Policy Integrity Enforcement
* **Microsoft Privileged Access Workstation (PAW) Guidance**: Hardening Group Policy Processing and Configuration Drift Prevention
