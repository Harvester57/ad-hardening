# [REQ-NET-011] Configure WMI Static Port

## Target Scope
* **Applicable Systems**: Domain Controllers, Member Servers.
* **Operating Systems**: Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**:
  * **WMI DCOM Endpoints Registry Key**: `HKLM\SOFTWARE\Classes\AppID\{8BC3F05E-D86B-11D0-A075-00C04FB68820}`
    * Value Name: `Endpoints`
    * Value Type: `REG_MULTI_SZ`
    * Value Data: `ncacn_ip_tcp,0,24158`
  * **WMI Service Type Configuration**: `HKLM\SYSTEM\CurrentControlSet\Services\winmgmt`
    * Value Name: `Type`
    * Value Type: `REG_DWORD`
    * Value Data: `16` (Decimal) (SERVICE_WIN32_OWN_PROCESS)

---

## Rationale
By default, Windows Management Instrumentation (WMI) runs in a shared svchost.exe process and dynamically allocates high-order TCP ports (49152-65535) for remote connections. This dynamic behavior prevents network administrators from implementing restrictive firewall policies, leaving the entire ephemeral port range exposed to the network.

Restricting WMI to a static port and process solves these security challenges:
1. **Attack Surface Reduction**: By configuring WMI to run on a static port (TCP 24158), administrators can block access to the generic high-order port range on perimeter firewalls while keeping WMI management accessible.
2. **Execution Isolation**: Moving WMI to a standalone host process prevents compromised shared services in the same svchost instance from tampering with management functions.
3. **Authentication Privacy**: Running `winmgmt.exe /standalonehost 6` sets the DCOM authentication level to `RPC_C_AUTHN_LEVEL_PKT_PRIVACY` (6). This enforces packet encryption for all WMI communications, mitigating man-in-the-middle (MITM) session hijacking and credential sniffing attacks.

---

## Legacy Impact & Compatibility
* **Service Interruption**: Changing the WMI service type and endpoints requires a restart of the `winmgmt` service and its dependent services. Because multiple critical Windows infrastructure services depend on WMI (such as IP Helper, User Access Logging, and SMS Agent Host), a system reboot is recommended to apply this control cleanly.
* **Network Communication**: Internal firewall appliances and host-based firewalls must have explicit allow rules permitting TCP port 24158 from the management subnets before applying this configuration.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

#### 1. Define Static WMI Port and Service Type via GPO Registry Preferences
1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Create or edit a GPO targeting the target systems (e.g., `GPO_Hardening_Firewall_Baseline`).
3. Navigate to:
   `Computer Configuration\Preferences\Windows Settings\Registry`
4. Define the following **Registry Items**:
   * **WMI Static Port Assignment**:
     * **Action**: `Update`
     * **Hive**: `HKEY_LOCAL_MACHINE`
     * **Key Path**: `SOFTWARE\Classes\AppID\{8BC3F05E-D86B-11D0-A075-00C04FB68820}`
     * **Value Name**: `Endpoints`
     * **Value Type**: `REG_MULTI_SZ`
     * **Value Data**: `ncacn_ip_tcp,0,24158` (Enter on a single line)
   * **WMI Standalone Process Type**:
     * **Action**: `Update`
     * **Hive**: `HKEY_LOCAL_MACHINE`
     * **Key Path**: `SYSTEM\CurrentControlSet\Services\winmgmt`
     * **Value Name**: `Type`
     * **Value Type**: `REG_DWORD`
     * **Value Data**: `16` (Decimal)

#### 2. Configure Inbound Windows Firewall Rules
Ensure a GPO firewall rule permits inbound TCP port 24158 originating only from authorized management/PAW network ranges.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following scripts locally to apply the WMI static port configuration.

#### Remediation Script:
[Download Script: Set-WMIStaticPort.ps1](implementation_scripts/Set-WMIStaticPort.ps1)

```powershell
# Set-WMIStaticPort.ps1
# Description: Configures WMI to run in a standalone host process on static TCP port 24158 with packet privacy.

Write-Host "Applying hardening requirement: Configure WMI Static Port..." -ForegroundColor Cyan

# 1. Configure the static TCP port 24158 for WMI AppID
$WmiAppIdPath = "HKLM:\SOFTWARE\Classes\AppID\{8BC3F05E-D86B-11D0-A075-00C04FB68820}"
if (-not (Test-Path $WmiAppIdPath)) {
    New-Item -Path $WmiAppIdPath -Force | Out-Null
}
# Set Endpoints string array
Set-ItemProperty -Path $WmiAppIdPath -Name "Endpoints" -Value @("ncacn_ip_tcp,0,24158") -Type MultiString
Write-Host "[+] Configured WMI AppID static endpoint to TCP 24158." -ForegroundColor Green

# 2. Configure WMI to run in a standalone host process with packet privacy
# This command sets HKLM\SYSTEM\CurrentControlSet\Services\winmgmt\Type to OWN_PROCESS (16)
# and configures the default authentication level to PKT_PRIVACY (6).
Write-Host "[+] Configuring WMI service to run as standalone process..." -ForegroundColor Gray
$Proc = Start-Process -FilePath "winmgmt.exe" -ArgumentList "/standalonehost 6" -Wait -NoNewWindow -PassThru

if ($Proc.ExitCode -eq 0) {
    Write-Host "[+] WMI standalone host configuration completed successfully." -ForegroundColor Green
} else {
    Write-Warning "[-] WMI standalone host configuration exited with code $($Proc.ExitCode)."
}

Write-Host "[!] Note: A system reboot is recommended to cleanly apply WMI process changes and restart all dependencies." -ForegroundColor Yellow
```

#### Audit Script:
[Download Script: Test-WMIStaticPort.ps1](audit_scripts/Test-WMIStaticPort.ps1)

```powershell
# Test-WMIStaticPort.ps1
# Description: Audits WMI static port registry configuration and standalone host settings.

Write-Host "Auditing WMI static port configuration..." -ForegroundColor Cyan
$vulnerable = $false

# 1. Audit AppID Endpoints Registry Setting
$WmiAppIdPath = "HKLM:\SOFTWARE\Classes\AppID\{8BC3F05E-D86B-11D0-A075-00C04FB68820}"
$EndpointsVal = Get-ItemProperty -Path $WmiAppIdPath -Name "Endpoints" -ErrorAction SilentlyContinue

if ($EndpointsVal) {
    $Endpoints = $EndpointsVal.Endpoints
    if ($Endpoints -contains "ncacn_ip_tcp,0,24158") {
        Write-Host "[+] WMI static port registry endpoint is configured correctly (TCP 24158)." -ForegroundColor Green
    } else {
        Write-Host "[!] NON-COMPLIANT: WMI Endpoints registry value is: '$($Endpoints -join ', ')' (Expected: 'ncacn_ip_tcp,0,24158')" -ForegroundColor Red
        $vulnerable = $true
    }
} else {
    Write-Host "[!] NON-COMPLIANT: Wmi AppID 'Endpoints' value is missing." -ForegroundColor Red
    $vulnerable = $true
}

# 2. Audit WMI Service Execution Type
$WinmgmtPath = "HKLM:\SYSTEM\CurrentControlSet\Services\winmgmt"
$TypeVal = Get-ItemProperty -Path $WinmgmtPath -Name "Type" -ErrorAction SilentlyContinue

if ($TypeVal) {
    $Type = $TypeVal.Type
    if ($Type -eq 16) {
        Write-Host "[+] WMI is configured to run as a standalone process (Type = 16)." -ForegroundColor Green
    } else {
        Write-Host "[!] NON-COMPLIANT: WMI service execution type is: $Type (Expected: 16 [OWN_PROCESS])" -ForegroundColor Red
        $vulnerable = $true
    }
} else {
    Write-Host "[!] NON-COMPLIANT: WMI service registry key is missing or inaccessible." -ForegroundColor Red
    $vulnerable = $true
}

if ($vulnerable) {
    Write-Host "Audit result: NON-COMPLIANT" -ForegroundColor Red
} else {
    Write-Host "Audit result: COMPLIANT" -ForegroundColor Green
}
```

---

## Sources & Compliance References
* **ANSSI AD Hardening Guide**: Recommendation R7 (Filtering and IPsec on Domain Controllers), Recommendation R8 (Administration network subnets / filtering rules)
* **CIS Windows Server Benchmark**: Section 19 (Windows Defender Firewall with Advanced Security)
* **DSInternals AD Firewall Guide (Michael Grafnetter)**: [Active Directory Firewall - Domain Controller Firewall](https://firewall.dsinternals.com/ADDS/)
