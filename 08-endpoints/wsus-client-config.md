# Hardening Requirement: WSUS Client Configuration

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers.
* **Operating Systems**: Windows 10 (and above) Enterprise/Professional, Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * Computer Configuration\Administrative Templates\Windows Components\Windows Update
  * HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate

---

## Rationale
In an isolated, air-gapped network, workstations cannot connect directly to Microsoft's online Update servers. If the system is left in its default configuration:
1. **DNS/Firewall Pollution**: Workstations will continuously attempt to resolve and connect to public Windows Update URLs (e.g., `*.update.microsoft.com`), filling firewall and local DNS resolver cache logs with timeouts and block events.
2. **Missing Updates**: Workstations will fail to receive security patches, critical updates, and Windows Defender definitions.
3. **Control Bypass**: Attackers or unapproved software could attempt to install out-of-band features or packages if update routes are not explicitly locked to internal sources.

Enforcing the intranet update service location redirects all system update queries to the local WSUS server.

---

## Legacy Impact & Compatibility
* **WSUS Dependency**: The local Windows Server Update Services (WSUS) server must remain online and functional. If the WSUS server is unreachable, workstations will be unable to query, download, or apply security patches.
* **Administrative Burden**: Enterprise administrators must manually synchronize the WSUS database (sneakernet transfer of metadata and updates) to ensure new patches are made available to clients.

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

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following scripts locally to configure registry keys to enforce local WSUS parameters.

```powershell
# Set-WSUSClientConfiguration.ps1
# Configures local registry keys to point the Windows Update client to the intranet WSUS server.

Write-Host "--- Configuring WSUS Client Settings ---" -ForegroundColor Cyan

$WUPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
$WUAUPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"

# 1. Create keys if they do not exist
if (-not (Test-Path $WUPath)) {
    New-Item -Path $WUPath -Force | Out-Null
}
if (-not (Test-Path $WUAUPath)) {
    New-Item -Path $WUAUPath -Force | Out-Null
}

# Define intranet WSUS URL
$WSUSServer = "http://local-wsus.domain.local:8530"

# 2. Configure update location and statistics server
Set-ItemProperty -Path $WUPath -Name "WUServer" -Value $WSUSServer -Type String
Set-ItemProperty -Path $WUPath -Name "WUStatusServer" -Value $WSUSServer -Type String
Set-ItemProperty -Path $WUPath -Name "DoNotConnectToWindowsUpdateInternetLocations" -Value 1 -Type DWord

# 3. Configure Automatic Updates behavior (AUOptions = 4: Auto Download & Schedule)
Set-ItemProperty -Path $WUAUPath -Name "NoAutoUpdate" -Value 0 -Type DWord
Set-ItemProperty -Path $WUAUPath -Name "AUOptions" -Value 4 -Type DWord
Set-ItemProperty -Path $WUAUPath -Name "UseWUServer" -Value 1 -Type DWord

Write-Host "[+] Local WSUS parameters applied." -ForegroundColor Green
```

*To audit the WSUS client configuration status:*
```powershell
# Test-WSUSClientStatus.ps1
# Audits registry values to verify WSUS server assignment.

Write-Host "--- Auditing WSUS Client Settings ---" -ForegroundColor Cyan

$WUPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
$WUAUPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"

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
```

---

## 🔗 Sources & Compliance References
* **CIS Microsoft Windows 10 Benchmark**: Section 18.2.2 (Specify intranet Microsoft update service location), Section 18.2.3 (Do not connect to any Windows Update Internet locations)
* **Microsoft Security Baselines**: Windows Update client baseline policies.
