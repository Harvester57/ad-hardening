# [REQ-END-132] User Profile: Group Policy Registry Policy Processing Behaviors

## Target Scope
* **Applicable Systems**: Tier 2 Client Workstations and Member Servers. *(For Tier 0 Privileged Access Workstations, refer to reciprocal baseline [REQ-PAW-121](../../07-paws/user-profile/configure-up-gp-processing.md)).*
* **Operating Systems**: Windows 10 Enterprise/Professional (all supported builds), Windows 11 Enterprise/Pro, Windows Server 2016, 2019, 2022, and 2025.

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
Group Policy processing in Windows relies on Client-Side Extensions (CSEs). Each CSE is registered under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions` with a unique GUID. The GUID `{35378EAC-683F-11D2-A89A-00C04FBBCFA2}` represents the primary **Registry Client-Side Extension** (`gptext.dll`), which is responsible for applying Administrative Templates (`.admx`/`.adml` policies) and direct registry modifications defined across applied Group Policy Objects.

### 1. Group Policy Processing Mechanics & Optimization Risks
By default, the Windows Group Policy engine (`gpsvc`) incorporates performance optimizations:
* During background refresh cycles (every 90 minutes by default, with a randomized 0 to 30-minute offset), the Group Policy client checks whether the version number of applied GPOs has incremented in Active Directory (`gpt.ini` in `SYSVOL`).
* If the GPO version has not changed, the engine treats the client configuration as unchanged and **skips processing** the Registry CSE.
* If a local user with administrative privileges, a rogue script, or malware modifies or deletes registry keys that were originally configured by Group Policy (e.g., disabling Windows Defender, re-enabling insecure legacy protocols, modifying audit flags, or altering firewall rules), the operating system will **never** automatically restore the baseline settings during periodic refreshes. The system remains in a drifted, compromised state until the domain GPO itself is modified or a manual `gpupdate /force` is executed locally.

### 2. Threat Mitigation & Self-Healing Registry Enforcement
* **Preventing Configuration Drift**: Setting `NoGPOListChanges = 0` ("Process even if the Group Policy objects have not changed") forces the Registry CSE to re-evaluate and re-apply all registry-based policy settings on every refresh interval, regardless of whether the GPO version number changed in Active Directory. This creates an automated self-healing mechanism that continually re-asserts security baselines.
* **Continuous Background Enforcement**: Setting `NoBackgroundPolicy = 0` guarantees that registry policies are applied during background processing intervals while users are logged in, rather than deferring policy application exclusively to system reboots or interactive user logons.
* **Resilience Against Defense Impairment**: If an adversary gains temporary local administrative privileges or executes living-off-the-land techniques to weaken endpoint defenses (e.g., flipping registry flags to blind endpoint detection agents), the Group Policy engine will automatically revert the unauthorized modifications within the next refresh window.

### 3. MITRE ATT&CK Mapping
* **T1484.001 - Domain Policy Modification: Group Policy Modification**: Ensuring local endpoints continuously re-assert centrally authorized domain policies.
* **T1562.001 - Impair Defenses: Disable or Modify Tools**: Neutralizing malware attempts to weaken security defenses via local registry manipulation by automatically overwriting drifted settings.
* **T1112 - Modify Registry**: Continually restoring unauthorized local registry modifications back to hardened baseline states.

---

## Legacy Impact & Compatibility
* **Minimal Performance Overhead**: Processing registry policy settings from cached `registry.pol` files requires minimal CPU cycles and completes in a few milliseconds on modern hardware.
* **Offline Operation**: When an endpoint is disconnected from the corporate network or domain controllers, the Group Policy client re-evaluates its local cache, preserving the hardened state without causing errors or delays.
* **Zero Software Incompatibility**: The policy only enforces configured GPO registry keys; unmanaged application settings remain unaffected.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to workstations and member servers (e.g., `GPO_Hardening_Endpoints`).
3. Navigate to: `Computer Configuration \ Administrative Templates \ System \ Group Policy`
4. Double-click **Configure Registry policy processing** and configure:
   * Select **Enabled**
   * Check **Process even if the Group Policy objects have not changed**
   * Ensure **Do not apply during periodic background processing** is **unchecked**
5. Link the GPO to the appropriate Organizational Unit and verify policy propagation using `gpupdate /force`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to configure the Registry CSE processing behaviors:

[Download Script: Configure-Upgpprocessing.ps1](../implementation_scripts/Configure-Upgpprocessing.ps1)

```powershell
# Configure-Upgpprocessing.ps1
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

[Download Script: Get-UpgpprocessingStatus.ps1](../audit_scripts/Get-UpgpprocessingStatus.ps1)

```powershell
# Get-UpgpprocessingStatus.ps1
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
* **ANSSI Active Directory Hardening Guide**: Client Security Baselines and Policy Integrity Enforcement
* **Microsoft Windows Group Policy Architecture**: MS-GPOL: Group Policy: Core Protocol and Client-Side Extensions Specification
