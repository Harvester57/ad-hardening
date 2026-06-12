# Hardening Requirement: Configure Dedicated WSUS for Tier 0

## Target Scope
* **Applicable Systems**: Domain Controllers, Tier 0 Administration Workstations (PAWs)
* **Operating Systems**: Windows Server 2016, Windows Server 2019, Windows Server 2022, Windows 10/11 Enterprise

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**: 
  * **GPO Path**: `Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Update\Specify intranet Microsoft update service location`
  * **Registry Location**: `HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate`

---

## Rationale
The Windows Server Update Services (WSUS) role allows administrators to centralize the approval and distribution of security updates and patches. However, update services execute code with system privileges.

If a shared, mutualized WSUS server (managed by Tier 1 or Tier 2 administrators) is used to patch Tier 0 Domain Controllers:
1. **Lateral Movement Target**: A compromise of the shared WSUS server or its database allows an attacker to inject malicious metadata, forcing Domain Controllers to execute arbitrary code or load compromised updates.
2. **Bypasses Administration Isolation**: Standard network administrators could inadvertently or maliciously deploy payloads to Tier 0 servers.
3. **HTTP Traffic Manipulation**: If WSUS communication is configured over cleartext HTTP (the default port 8530), attackers inside the network can perform man-in-the-middle attacks to inject custom update packages.

To mitigate these threats, Tier 0 Domain Controllers and PAWs must pull updates from a dedicated WSUS server located inside the Tier 0 security boundary, configured exclusively with SSL/TLS encryption.

---

## Legacy Impact & Compatibility
* **Operational Overhead**: Dedicating a separate WSUS server for Tier 0 assets means updates must be reviewed, approved, and synchronized separately from standard enterprise updates.
* **Network Traffic**: Ensure that firewall rules permit the dedicated Tier 0 WSUS server to connect outbound to Microsoft Update servers to synchronize updates.
* **Certificate Management**: Enabling SSL/TLS on WSUS requires generating and trusting a certificate on all Tier 0 client systems (DCs and PAWs).

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration

#### 1. Enforce HTTPS for WSUS in GPO
1. Open **Group Policy Management** (`gpmc.msc`).
2. Create or edit a GPO targeting Tier 0 systems (e.g., `GPO_Hardening_DomainControllers`).
3. Navigate to:
   `Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Update`
4. Double-click the **Specify intranet Microsoft update service location** policy.
5. Set it to **Enabled**.
6. Set the intranet update service and status server properties to point to the dedicated, secure Tier 0 WSUS server:
   * **Set the intranet update service for detecting updates**: `https://wsust0.corp.local:8531`
   * **Set the intranet statistics server**: `https://wsust0.corp.local:8531`
   * **Set the alternate download server**: `https://wsust0.corp.local:8531`
7. Click **OK** and link the GPO to the Domain Controllers and PAW OUs.

#### 2. Configure SSL on the WSUS Server
On the dedicated Tier 0 WSUS server:
1. Open **IIS Manager** (`inetmgr.exe`).
2. Bind an SSL certificate (issued by a trusted PKI) to port 8531 on the WSUS Administration Web Site.
3. In the middle pane, double-click **SSL Settings** on the virtual directories (`SimpleAuthWebService`, `DSSAuthWebService`, `ClientWebService`, `APIRemoting30`).
4. Check **Require SSL** and click **Apply**.
5. Execute the WSUS configuration command to activate SSL bindings:
   `C:\Program Files\Update Services\Tools\wsusutil.exe configuressl wsust0.corp.local`

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script block to apply the dedicated WSUS target server configuration locally via registry parameters.

[Download Script: Set-LocalWsusServer.ps1](implementation_scripts/Set-LocalWsusServer.ps1)

```powershell
# Set-LocalWsusServer.ps1
# Description: Configures the local client registry to utilize the dedicated Tier 0 WSUS over HTTPS.

Write-Host "Applying hardening requirement: Configure Dedicated WSUS for Tier 0..." -ForegroundColor Cyan

$WsusRegPath = "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate"
$WsusServerUrl = "https://wsust0.corp.local:8531"

if (-not (Test-Path $WsusRegPath)) {
    New-Item -Path $WsusRegPath -Force | Out-Null
}

# 1. Configure target WSUS server values
Set-ItemProperty -Path $WsusRegPath -Name "WUServer" -Value $WsusServerUrl -Type String -ErrorAction Stop
Set-ItemProperty -Path $WsusRegPath -Name "WUStatusServer" -Value $WsusServerUrl -Type String -ErrorAction Stop

# 2. Force Windows Update configuration to use local settings
$UpdateAuPath = "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU"
if (-not (Test-Path $UpdateAuPath)) {
    New-Item -Path $UpdateAuPath -Force | Out-Null
}
Set-ItemProperty -Path $UpdateAuPath -Name "UseWUServer" -Value 1 -Type DWord -ErrorAction Stop

Write-Host "[+] Local system configured to use secure WSUS server: $WsusServerUrl" -ForegroundColor Green
```

*To verify active WSUS configurations:*
[Download Script: Get-WsusConfigStatus.ps1](audit_scripts/Get-WsusConfigStatus.ps1)

```powershell
# Get-WsusConfigStatus.ps1
# Description: Audits local WSUS configuration settings.

$WsusRegPath = "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate"

Write-Host "Checking Windows Update registry parameters..." -ForegroundColor Cyan

if (Test-Path $WsusRegPath) {
    $WusVal = Get-ItemProperty -Path $WsusRegPath -Name "WUServer" -ErrorAction SilentlyContinue
    if ($null -ne $WusVal) {
        $WusServer = $WusVal.WUServer
        
        # Check if using HTTPS
        if ($WusServer -like "https://*") {
            Write-Host "[+] WUServer: $WusServer (Secure HTTPS Connection)." -ForegroundColor Green
        } else {
            Write-Host "[-] WUServer: $WusServer (Insecure HTTP Connection - Action Required)." -ForegroundColor Red
        }
    } else {
        Write-Host "[-] WUServer is not configured." -ForegroundColor Yellow
    }
} else {
    Write-Host "[-] Windows Update policies are not defined." -ForegroundColor Yellow
}
```

---

## Sources & Compliance References
* **ANSSI AD Hardening Guide**: Section 3.6.2 (Windows Server Update Services), Section 9
* **ANSSI Remediation of Active Directory Tier 0 Guide**: Section 3.d (Page 23), Section 7 (Page 46)
* **Microsoft Security Guidance**: Configure WSUS in a Multi-Tier Environment Securely
