# [REQ-PAW-122] User Profile: Telemetry and Inventory Collection Restrictions for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration. *(For Tier 2 Client Workstations and Member Servers, refer to reciprocal baseline [REQ-END-133](../../08-endpoints/user-profile/configure-up-telemetry-inventory.md)).*
* **Operating Systems**: Windows 10 Enterprise (1607+) and Windows 11 Enterprise.

---

## Implementation Details
* **Priority**: Medium
* **GPO Paths / Registry Locations**:
  * **Turn off Inventory Collector**:
    * GPO Path: `Computer Configuration\Administrative Templates\Windows Components\Application Compatibility\Turn off Inventory Collector` -> Set to **Enabled**
    * Registry Path: `HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat`
    * Value Name: `DisableInventory`
    * Value Type: `REG_DWORD`
    * Value Data: `1` (Turn off application compatibility inventory scans)
  * **Allow Diagnostic Data / Telemetry**:
    * GPO Path: `Computer Configuration\Administrative Templates\Windows Components\Data Collection and Preview Builds\Allow Diagnostic Data` (or `Allow Telemetry`) -> Set to **Enabled**, configured to **1 - Send required diagnostic data** (or **0 - Diagnostic data off** if supported by enterprise licensing)
    * Registry Path: `HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection`
    * Value Name: `AllowTelemetry`
    * Value Type: `REG_DWORD`
    * Value Data: `1` (Restrict diagnostic telemetry to Required/Basic level)
  * **Limit Enhanced Diagnostic Data for Windows Analytics**:
    * GPO Path: `Computer Configuration\Administrative Templates\Windows Components\Data Collection and Preview Builds\Limit Enhanced diagnostic data to the minimum required by Windows Analytics` -> Set to **Enabled**
    * Registry Path: `HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection`
    * Value Name: `LimitEnhancedDiagnosticDataWindowsAnalytics`
    * Value Type: `REG_DWORD`
    * Value Data: `1` (Restrict enhanced diagnostic data collection to IT analytics telemetry only)

---

## Rationale
Privileged Access Workstations (PAWs) serve as the most secure bastion tier in an enterprise Active Directory deployment, operating within isolated administrative networks with strictly regulated inbound and outbound communications. Telemetry, diagnostic data collection, and application inventory background tasks represent unnecessary attack surface and data leakage risks when running on Tier 0 consoles.

### 1. Application Compatibility Inventory Hazards on Tier 0 Systems
The Windows Inventory Collector (`CompatTelRunner.exe`) periodically performs intensive scans of the local filesystem and registry to build compatibility databases (`Amcache.hve`):
* On a PAW, administrative tools, proprietary maintenance scripts, emergency recovery utilities, and custom PowerShell modules are regularly executed.
* The Inventory Collector catalogs metadata for all executed binaries and scripts, recording file paths, internal names, execution timestamps, and cryptographic hashes.
* If an attacker establishes initial low-privilege foothold on the network, local or transmitted inventory caches provide high-fidelity intelligence detailing the exact toolset and defensive posture deployed on the administrative tier.
* Enforcing `DisableInventory = 1` stops the inventory scanner completely, saving I/O overhead and eliminating local inventory artifact generation.

### 2. Preventing Administrative Data Egress and Crash Dump Leakage
Standard Windows telemetry can capture detailed diagnostic events, error reports, and in some circumstances, partial process memory dumps when an application crashes:
* If a Tier 0 administrative tool (such as Active Directory Users and Computers, `adsi.edit`, or an elevated PowerShell administrative session) crashes, unconstrained telemetry could attempt to upload diagnostic dumps to public cloud endpoints.
* Such crash dumps could inadvertently contain sensitive Tier 0 operational data, Active Directory object attributes, or transient credentials.
* Enforcing `AllowTelemetry = 1` (or `0` on Windows Enterprise with security telemetry disabled) and `LimitEnhancedDiagnosticDataWindowsAnalytics = 1` ensures that no extended diagnostic memory dumps, user interaction traces, or system telemetry can egress from the PAW environment.

### 3. MITRE ATT&CK Mapping
* **T1082 - System Information Discovery**: Preventing adversaries from mining local compatibility and inventory caches for Tier 0 tool discovery.
* **T1592 - Gather Victim Host Information**: Concealing administrative application inventories and host configuration parameters.
* **T1020 - Automated Exfiltration**: Restricting outbound diagnostic communication channels from isolated administrative tiers.

---

## Legacy Impact & Compatibility
* **Zero Disruption for Administrative Operations**: Disabling inventory scans and limiting telemetry has no impact on Active Directory administration tools (RSAT), PowerShell Remoting, or native Windows management consoles.
* **Network Hygiene**: Drastically reduces unsolicited outbound connections from the dedicated PAW management VLAN to external Microsoft endpoints, simplifying firewall rules and egress proxy monitoring.
* **System Performance**: Eliminates periodic disk thrashing and CPU spikes associated with `CompatTelRunner.exe` and `DiagTrack` background scans.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to the PAW Organizational Unit (e.g., `GPO_Hardening_PAWs`).
3. Navigate to: `Computer Configuration \ Administrative Templates \ Windows Components \ Application Compatibility`
   * Double-click **Turn off Inventory Collector** -> Select **Enabled**.
4. Navigate to: `Computer Configuration \ Administrative Templates \ Windows Components \ Data Collection and Preview Builds`
   * Double-click **Allow Diagnostic Data** (or **Allow Telemetry**) -> Select **Enabled**, and choose **Send required diagnostic data** (or **Diagnostic data off** / `0` if available).
   * Double-click **Limit Enhanced diagnostic data to the minimum required by Windows Analytics** -> Select **Enabled**.
5. Link the GPO to the dedicated PAW Organizational Unit and enforce policy application with `gpupdate /force`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to enforce inventory and telemetry restrictions on PAWs:

[Download Script: Configure-PawUptelemetryinventory.ps1](../implementation_scripts/Configure-PawUptelemetryinventory.ps1)

```powershell
# Configure-PawUptelemetryinventory.ps1
Write-Host "Applying User Profile restriction: telemetry-inventory..." -ForegroundColor Cyan

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
Set-RegValue "HKLM:" "SOFTWARE\Policies\Microsoft\Windows\AppCompat" "DisableInventory" "1" "DWord"
Set-RegValue "HKLM:" "SOFTWARE\Policies\Microsoft\Windows\DataCollection" "AllowTelemetry" "1" "DWord"
Set-RegValue "HKLM:" "SOFTWARE\Policies\Microsoft\Windows\DataCollection" "LimitEnhancedDiagnosticDataWindowsAnalytics" "1" "DWord"

```

*To audit the hardening status:*

[Download Script: Get-PawUptelemetryinventoryStatus.ps1](../audit_scripts/Get-PawUptelemetryinventoryStatus.ps1)

```powershell
# Get-PawUptelemetryinventoryStatus.ps1
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
Test-RegValue "HKLM:" "SOFTWARE\Policies\Microsoft\Windows\AppCompat" "DisableInventory" "1"
Test-RegValue "HKLM:" "SOFTWARE\Policies\Microsoft\Windows\DataCollection" "AllowTelemetry" "1"
Test-RegValue "HKLM:" "SOFTWARE\Policies\Microsoft\Windows\DataCollection" "LimitEnhancedDiagnosticDataWindowsAnalytics" "1"

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
* **CIS Microsoft Windows 10 Enterprise Benchmark**: Section 18.9.4.1 (L1 - Ensure 'Turn off Inventory Collector' is set to 'Enabled'); Section 18.9.14.1 (L1 - Ensure 'Allow Diagnostic Data' is set to 'Enabled')
* **CIS Microsoft Windows 11 Enterprise Benchmark**: Section 18.9.4.1; Section 18.9.14.1
* **DISA STIG**: Windows 10 STIG Rules WN10-CC-000005, WN10-CC-000010; Windows 11 STIG Rules WN11-CC-000005, WN11-CC-000010
* **ANSSI Active Directory Hardening Guide**: Workstation Baseline Guide and Restricting Data Egress on Privileged Consoles
* **Microsoft Privileged Access Workstation (PAW) Security Baseline**: Network and Telemetry Isolation Controls
