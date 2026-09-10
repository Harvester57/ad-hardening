# [REQ-END-133] User Profile: Telemetry and Inventory Collection Restrictions

## Target Scope
* **Applicable Systems**: Tier 2 Client Workstations and Member Servers. *(For Tier 0 Privileged Access Workstations, refer to reciprocal baseline [REQ-PAW-122](../../07-paws/user-profile/configure-up-telemetry-inventory.md)).*
* **Operating Systems**: Windows 10 Enterprise/Professional (all supported builds), Windows 11 Enterprise/Pro, Windows Server 2016, 2019, 2022, and 2025.

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
    * GPO Path: `Computer Configuration\Administrative Templates\Windows Components\Data Collection and Preview Builds\Allow Diagnostic Data` (or `Allow Telemetry`) -> Set to **Enabled**, configured to **1 - Send required diagnostic data** (or **1 - Basic**)
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
Modern Windows operating systems include background diagnostic, telemetry, and inventory scanning subsystems designed to evaluate system health, application compatibility, and user experience telemetry. These subsystems are driven primarily by the **Connected User Experiences and Telemetry** service (`DiagTrack`) and the **Microsoft Compatibility Appraiser** scheduled task (`CompatTelRunner.exe`).

While helpful in consumer environments, uncontrolled inventory collection and extensive diagnostic data uploads introduce distinct operational and security risks in hardened enterprise deployments.

### 1. Inventory Collector & Application Compatibility Mechanics
The Windows Application Compatibility Inventory Collector (`CompatTelRunner.exe`) periodically crawls the local filesystem, registry, and application databases to compile comprehensive inventories of:
* Every installed binary, portable executable (PE), driver, and dynamically linked library (`.dll`).
* File paths, hashes, compilation timestamps, and digital signatures stored locally in `C:\Windows\AppCompat\Programs\Amcache.hve`.
* Device hardware identifiers, peripheral configurations, and firmware versions.

This inventory process generates significant periodic disk I/O and CPU spikes. More critically, an attacker with local user access can query these inventory stores or leverage artifact caches for local reconnaissance, discovering specific vulnerable software versions, custom in-house tools, or unpatched utilities installed across the fleet. Setting `DisableInventory = 1` disables the Inventory Collector, suppressing automated software enumeration.

### 2. Diagnostic Data Telemetry & Information Disclosure
Windows telemetry operates across several tier levels (0 = Security/Off, 1 = Basic/Required, 2 = Enhanced, 3 = Full/Optional):
* At higher telemetry levels (Enhanced or Full), Windows transmits detailed operational data to external Microsoft telemetry gateways (`v10.events.data.microsoft.com`).
* This data can include advanced diagnostic logs, crash dumps containing portions of process memory, user interface interactions, and internal network diagnostic events.
* In sensitive enterprise environments, unconstrained telemetry transmission creates the risk of inadvertent data leakage—exposing internal server names, IP addressing schemes, proprietary software naming conventions, and script execution paths to external networks.
* Enforcing `AllowTelemetry = 1` and `LimitEnhancedDiagnosticDataWindowsAnalytics = 1` bounds data collection strictly to the minimum required operating system health metrics (hardware specs, crash error codes, and update compatibility signals), preventing the transmission of verbose process memory or user interaction logs.

### 3. MITRE ATT&CK Mapping
* **T1082 - System Information Discovery**: Preventing local attackers from exploiting automated inventory caches (`Amcache.hve`) compiled by compatibility scanners.
* **T1592 - Gather Victim Host Information**: Minimizing the exposure of internal system architecture, driver versions, and software footprints.
* **T1020 - Automated Exfiltration**: Restricting outbound diagnostic data channels to prevent unvetted background transmissions of host telemetry.

---

## Legacy Impact & Compatibility
* **Enterprise Management**: Disabling the Application Compatibility Inventory Collector does **not** impede enterprise systems management solutions such as Microsoft Intune, Microsoft Endpoint Configuration Manager (MECM), or third-party asset inventory agents.
* **Windows Update for Business**: Restricting telemetry to Level 1 (Required/Basic) fully preserves Windows Update functionality, feature update servicing, and security patch deployment.
* **Network Bandwidth**: Eliminating unnecessary diagnostic payload uploads reduces egress network traffic across remote office links and proxy gateways.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to workstations and member servers (e.g., `GPO_Hardening_Endpoints`).
3. Navigate to: `Computer Configuration \ Administrative Templates \ Windows Components \ Application Compatibility`
   * Double-click **Turn off Inventory Collector** -> Select **Enabled**.
4. Navigate to: `Computer Configuration \ Administrative Templates \ Windows Components \ Data Collection and Preview Builds`
   * Double-click **Allow Diagnostic Data** (or **Allow Telemetry**) -> Select **Enabled**, and choose **Send required diagnostic data** (or **1 - Basic**).
   * Double-click **Limit Enhanced diagnostic data to the minimum required by Windows Analytics** -> Select **Enabled**.
5. Link the GPO to the target Organizational Unit and enforce policy application with `gpupdate /force`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to enforce inventory and telemetry restrictions:

[Download Script: Configure-Uptelemetryinventory.ps1](../implementation_scripts/Configure-Uptelemetryinventory.ps1)

```powershell
# Configure-Uptelemetryinventory.ps1
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

[Download Script: Get-UptelemetryinventoryStatus.ps1](../audit_scripts/Get-UptelemetryinventoryStatus.ps1)

```powershell
# Get-UptelemetryinventoryStatus.ps1
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
* **CIS Microsoft Windows 10 Enterprise Benchmark**: Section 18.9.4.1 (L1 - Ensure 'Turn off Inventory Collector' is set to 'Enabled'); Section 18.9.14.1 (L1 - Ensure 'Allow Diagnostic Data' is set to 'Enabled: Diagnostic data off' or 'Send required diagnostic data')
* **CIS Microsoft Windows 11 Enterprise Benchmark**: Section 18.9.4.1; Section 18.9.14.1
* **DISA STIG**: Windows 10 STIG Rules WN10-CC-000005, WN10-CC-000010; Windows 11 STIG Rules WN11-CC-000005, WN11-CC-000010
* **ANSSI Hardening Guidelines for Windows 10/11**: Minimizing Operating System Telemetry and Diagnostic Data Exfiltration
* **Microsoft Privacy Documentation**: Configure Windows Diagnostic Data in Your Organization
