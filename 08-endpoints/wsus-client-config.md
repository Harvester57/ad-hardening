# Hardening Requirement: WSUS Client Configuration

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers.
* **Operating Systems**: Windows 10 (and above) Enterprise/Professional, Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **GPO Paths**:
    * `Computer Configuration\Administrative Templates\Windows Components\Windows Update`
    * `Computer Configuration\Administrative Templates\Windows Components\Delivery Optimization`
  * **Registry Locations**:
    * `HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate`
      * `WUServer` (REG_SZ)
      * `WUStatusServer` (REG_SZ)
      * `DoNotConnectToWindowsUpdateInternetLocations` = `1` (REG_DWORD)
    * `HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU`
      * `NoAutoUpdate` = `0` (REG_DWORD)
      * `AUOptions` = `4` (REG_DWORD)
      * `UseWUServer` = `1` (REG_DWORD)
    * `HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization`
      * `DODownloadMode` = `2` (REG_DWORD)

---

## Rationale
In an isolated, air-gapped network, workstations cannot connect directly to Microsoft's online Update servers. If the system is left in its default configuration:
1. **DNS/Firewall Pollution**: Workstations will continuously attempt to resolve and connect to public Windows Update URLs (e.g., `*.update.microsoft.com`), filling firewall and local DNS resolver cache logs with timeouts and block events.
2. **Missing Updates**: Workstations will fail to receive security patches, critical updates, and Windows Defender definitions.
3. **Control Bypass**: Attackers or unapproved software could attempt to install out-of-band features or packages if update routes are not explicitly locked to internal sources.

Enforcing the intranet update service location redirects all system update queries to the local WSUS server. Furthermore, enforcing Windows **Delivery Optimization** download mode to `Group (2)` limits peer-to-peer update sharing strictly to computers within the same active directory domain/group or local subnet boundaries, reducing bandwidth constraints on WAN/intranet segments and preventing unmanaged peer sharing.

---

## Legacy Impact & Compatibility
* **WSUS Dependency**: The local Windows Server Update Services (WSUS) server must remain online and functional. If the WSUS server is unreachable, workstations will be unable to query, download, or apply security patches.
* **Administrative Burden**: Enterprise administrators must manually synchronize the WSUS database (sneakernet transfer of metadata and updates) to ensure new patches are made available to clients.
* **Delivery Optimization limits**: Group mode restricts Delivery Optimization cache sharing to standard networks. If endpoints span multiple separated sites without route aggregation, update replication times could increase slightly.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Create or edit a GPO linked to the workstations OU (e.g., `GPO_Hardening_Workstations`).
3. Navigate to:
   `Computer Configuration\Administrative Templates\Windows Components\Windows Update`
4. Configure the following settings:
   * **Policy**: `Configure Automatic Updates`
     * **Setting**: `Enabled`
     * **Configure automatic updating**: `4 - Auto download and schedule the install`
5. Configure the service location:
   * **Policy**: `Specify intranet Microsoft update service location`
     * **Setting**: `Enabled`
     * **Set the intranet update service for detecting updates**: `http://local-wsus.domain.local:8530` (Replace with your internal WSUS FQDN or IP)
     * **Set the intranet statistics server**: `http://local-wsus.domain.local:8530`
6. Navigate to:
   * **Policy**: `Do not connect to any Windows Update Internet locations`
     * **Setting**: `Enabled` (blocks fallback to public servers)
7. Navigate to:
   `Computer Configuration\Administrative Templates\Windows Components\Delivery Optimization`
8. Configure the following settings:
   * **Policy**: `Download Mode`
     * **Setting**: `Enabled`
     * **Download Mode**: `Group (2)`

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following scripts locally to configure registry keys to enforce local WSUS parameters and Delivery Optimization download mode.

[Download Script: Set-WSUSClientConfiguration.ps1](implementation_scripts/Set-WSUSClientConfiguration.ps1)

```powershell
# Set-WSUSClientConfiguration.ps1
# Configures local registry keys to point the Windows Update client to the intranet WSUS server and enforces DO Group mode.

Write-Host "--- Configuring WSUS Client Settings ---" -ForegroundColor Cyan

$WUPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
$WUAUPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
$DOPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization"

# 1. Create keys if they do not exist
if (-not (Test-Path $WUPath)) {
    New-Item -Path $WUPath -Force | Out-Null
}
if (-not (Test-Path $WUAUPath)) {
    New-Item -Path $WUAUPath -Force | Out-Null
}
if (-not (Test-Path $DOPath)) {
    New-Item -Path $DOPath -Force | Out-Null
}

# Define intranet WSUS URL
$WSUSServer = "http://local-wsus.domain.local:8530"

# 2. Configure update location and statistics server
Set-ItemProperty -Path $WUPath -Name "WUServer" -Value $WSUSServer -Type String -Force
Set-ItemProperty -Path $WUPath -Name "WUStatusServer" -Value $WSUSServer -Type String -Force
Set-ItemProperty -Path $WUPath -Name "DoNotConnectToWindowsUpdateInternetLocations" -Value 1 -Type DWord -Force

# 3. Configure Automatic Updates behavior (AUOptions = 4: Auto Download & Schedule)
Set-ItemProperty -Path $WUAUPath -Name "NoAutoUpdate" -Value 0 -Type DWord -Force
Set-ItemProperty -Path $WUAUPath -Name "AUOptions" -Value 4 -Type DWord -Force
Set-ItemProperty -Path $WUAUPath -Name "UseWUServer" -Value 1 -Type DWord -Force

# 4. Enforce DODownloadMode = 2 (Group)
Set-ItemProperty -Path $DOPath -Name "DODownloadMode" -Value 2 -Type DWord -Force

Write-Host "[+] Local WSUS parameters and Delivery Optimization download mode applied." -ForegroundColor Green
```

*To audit the WSUS client configuration status:*
[Download Script: Test-WSUSClientStatus.ps1](audit_scripts/Test-WSUSClientStatus.ps1)

```powershell
# Test-WSUSClientStatus.ps1
# Audits registry values to verify WSUS server assignment and Delivery Optimization configuration.

Write-Host "--- Auditing WSUS Client Settings ---" -ForegroundColor Cyan

$WUPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
$WUAUPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
$DOPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization"

$WUServerProp = Get-ItemProperty -Path $WUPath -Name "WUServer" -ErrorAction SilentlyContinue
$WUStatusProp = Get-ItemProperty -Path $WUPath -Name "WUStatusServer" -ErrorAction SilentlyContinue
$UseWUServerProp = Get-ItemProperty -Path $WUAUPath -Name "UseWUServer" -ErrorAction SilentlyContinue

$WUServerVal = if ($WUServerProp) { $WUServerProp.WUServer } else { "" }
$WUStatusVal = if ($WUStatusProp) { $WUStatusProp.WUStatusServer } else { "" }
$UseWUVal = if ($UseWUServerProp) { $UseWUServerProp.UseWUServer } else { 0 }

$ServerColor = if ($WUServerVal -like "http*") { "Green" } else { "Red" }
$UseColor = if ($UseWUVal -eq 1) { "Green" } else { "Red" }

Write-Host "    - Intranet WUServer: $WUServerVal" -ForegroundColor $ServerColor
Write-Host "    - Intranet WUStatusServer: $WUStatusVal" -ForegroundColor $ServerColor
Write-Host "    - UseWUServer Active: $UseWUVal (Required = 1)" -ForegroundColor $UseColor

# Audit Delivery Optimization
$DOVal = if (Test-Path $DOPath) { (Get-ItemProperty -Path $DOPath -Name "DODownloadMode" -ErrorAction SilentlyContinue).DODownloadMode } else { $null }
$DOColor = if ($DOVal -eq 2) { "Green" } else { "Red" }
Write-Host "    - Delivery Optimization DODownloadMode: $($DOVal | Out-String).Trim() (Expected = 2)" -ForegroundColor $DOColor
```

---

## 🔗 Sources & Compliance References
* **CIS Microsoft Windows 10 Benchmark**: Section 18.2.2 (Specify intranet Microsoft update service location), Section 18.2.3 (Do not connect to any Windows Update Internet locations)
* **Microsoft Security Baselines**: Windows Update client baseline policies.
* **DoD Windows 11 STIG**: Delivery Optimization DODownloadMode configuration requirements.
