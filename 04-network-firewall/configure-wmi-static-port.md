# [REQ-NET-011] Configure WMI Static Port and Service Hardening

## Target Scope
* **Applicable Systems**: Domain Controllers, Member Servers.
* **Operating Systems**: Windows Server 2016 (and above).

> [!NOTE]
> Client workstations and Privileged Access Workstations (PAWs) must not expose remote WMI endpoints. Inbound remote management protocols on endpoints are blocked entirely by workstation isolation controls (**[REQ-NET-003]**) and Defender Attack Surface Reduction (ASR) rules (**[REQ-PAW-088]** and **[REQ-END-092]**).

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **WMI DCOM Endpoints Registry Key**: `HKLM\SOFTWARE\Classes\AppID\{8BC3F05E-D86B-11D0-A075-00C04FB68820}`
    * Value Name: `Endpoints`
    * Value Type: `REG_MULTI_SZ`
    * Value Data: `ncacn_ip_tcp,0,24158`
  * **WMI DCOM Authentication Level**: `HKLM\SOFTWARE\Classes\AppID\{8BC3F05E-D86B-11D0-A075-00C04FB68820}`
    * Value Name: `AuthenticationLevel`
    * Value Type: `REG_DWORD`
    * Value Data: `6` (Decimal) (`RPC_C_AUTHN_LEVEL_PKT_PRIVACY`)
  * **WMI Service Type Configuration**: `HKLM\SYSTEM\CurrentControlSet\Services\winmgmt`
    * Value Name: `Type`
    * Value Type: `REG_DWORD`
    * Value Data: `16` (Decimal) (`SERVICE_WIN32_OWN_PROCESS`)
  * **Windows Defender Firewall with Advanced Security**:
    * Rule Name: `AD-Hardening-WMI-StaticPort-In`
    * Protocol: `TCP`
    * Local Port: `24158`
    * Remote Port: `Any`
    * Remote IP Addresses: Scoped strictly to authorized Tier 1 / PAW subnets or Admin Bastion hosts (must never be `Any`)
    * Action: `Allow connection`
    * State: `Enabled`
    * Profiles: `Domain, Private`

---

## Rationale
Windows Management Instrumentation (WMI) is a core Windows administration framework built upon the Distributed Component Object Model (DCOM) and Remote Procedure Call (RPC) protocols. By default, WMI runs inside a shared service host process (`svchost.exe -k netsvcs`) and dynamically allocates ephemeral high-order TCP ports (range `49152-65535`) for remote client connections.

Leaving WMI in its default configuration presents four critical security risks:

1. **The Dynamic RPC Port Dilemma & Attack Surface Exposure**:
   Because remote WMI clients dynamically negotiate communication ports via the RPC Endpoint Mapper (RPCSS on TCP port 135), network administrators who allow remote WMI must either open the entire ephemeral dynamic port range (`49152-65535`) on network firewalls or disable host firewalls entirely. Opening thousands of dynamic ports circumvents perimeter filtering and exposes every local service listening on high-order sockets to unauthorized network traversal. Pinning WMI to a dedicated static port (TCP `24158`) allows network and host firewalls to block the broad dynamic range and enforce strict microsegmentation.

2. **Lateral Movement and Living-off-the-Land Exploitation (MITRE ATT&CK T1047)**:
   Adversaries frequently leverage WMI to orchestrate stealthy lateral movement, execute remote code, query system configuration, and deploy backdoors without triggering interactive logon events (Event ID 4624 Type 3 network logons). Widely abused post-exploitation toolkits (such as Impacket's `wmiexec.py`, SharpWMI, and PowerShell CIM cmdlets) abuse DCOM interfaces to spawn malicious processes under `WmiPrvSE.exe` (e.g., `Win32_Process.Create`). Restricting WMI to static port 24158 and strictly scoping firewall access to authorized PAW subnets eliminates unmonitored cross-subnet living-off-the-land attacks.

3. **Wire Eavesdropping and Session Tampering Mitigation (CVE-2021-26414)**:
   Remote DCOM communications that operate below authentication level 6 (`RPC_C_AUTHN_LEVEL_PKT_PRIVACY`) do not encrypt payload data. Attackers positioned on the network path could intercept sensitive administrative data returned in WMI queries (such as system configurations, installed software inventories, environment variables, or process lists) or tamper with in-flight RPC commands. Enforcing `AuthenticationLevel = 6` mandates packet-level Kerberos or NTLM encryption across all WMI communications, fully satisfying Microsoft DCOM security hardening requirements (KB5004442).

4. **Process Isolation and Memory Containment**:
   By default, the `winmgmt` service shares a single `svchost.exe` process instance with multiple other system services (such as IP Helper, Background Intelligent Transfer Service, and Windows Update). Moving WMI into a standalone host process (`SERVICE_WIN32_OWN_PROCESS`, `Type = 16`) isolates its heap, thread pools, security tokens, and memory space. If an adjacent service running in a shared host process is compromised, process isolation prevents direct in-memory manipulation, token stealing, or tampering with directory management capabilities.

---

## Legacy Impact & Compatibility
* **Enterprise Management & Monitoring Tooling**:
  Centralized infrastructure monitoring agents and management platforms (e.g., Microsoft System Center Operations Manager [SCOM], Microsoft Configuration Manager [MECM/SCCM], SolarWinds, PRTG Network Monitor, Nagios) that perform remote WMI polling must be configured to communicate across firewalls on TCP port 24158. Host and network firewall rules must permit TCP 24158 between monitoring servers and target systems before enforcement.
* **DCOM Packet Privacy Enforcement**:
  Enforcing `AuthenticationLevel = 6` requires all remote clients and management scripts to negotiate packet privacy (`RPC_C_AUTHN_LEVEL_PKT_PRIVACY`). Legacy administration tools, scripts, or non-Windows WMI libraries that attempt connections with lower authentication levels (such as `RPC_C_AUTHN_LEVEL_CONNECT` or `CALL`) will fail with error `0x80070005 (E_ACCESSDENIED)` or `0x80010111`. Modern PowerShell (`Get-CimInstance`, `Invoke-CimMethod`) uses packet privacy by default over WSMAN/DCOM.
* **Service Interruption and Host Reboot Prerequisites**:
  Changing the `winmgmt` service type from shared (`32`) to standalone (`16`) requires restarting the service. Multiple essential Windows infrastructure services depend directly on WMI (including `iphlpsvc` [IP Helper], `wscsvc` [Security Center], `smsvss` [SMS Agent Host], `SharedAccess` [Internet Connection Sharing], and Hyper-V host management). Stopping `winmgmt` in a running production environment can cause transient dependent service outages. A scheduled maintenance window with a host reboot is strongly recommended to apply these changes cleanly.
* **Strategic Migration to WinRM**:
  WMI over DCOM is a legacy remote management architecture. Organizations should treat static port assignment as a defense-in-depth measure while migrating remote administration workflows to Windows Remote Management (WinRM / PowerShell Remoting over HTTPS port 5986), which is firewall-friendly, stateless, and natively segmented (**[REQ-NET-010]**).

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

#### 1. Define Static WMI Port, Packet Privacy, and Service Type via GPO Registry Preferences
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
   * **WMI DCOM Packet Privacy Authentication Level**:
     * **Action**: `Update`
     * **Hive**: `HKEY_LOCAL_MACHINE`
     * **Key Path**: `SOFTWARE\Classes\AppID\{8BC3F05E-D86B-11D0-A075-00C04FB68820}`
     * **Value Name**: `AuthenticationLevel`
     * **Value Type**: `REG_DWORD`
     * **Value Data**: `6` (Decimal)
   * **WMI Standalone Process Type**:
     * **Action**: `Update`
     * **Hive**: `HKEY_LOCAL_MACHINE`
     * **Key Path**: `SYSTEM\CurrentControlSet\Services\winmgmt`
     * **Value Name**: `Type`
     * **Value Type**: `REG_DWORD`
     * **Value Data**: `16` (Decimal)

#### 2. Configure Windows Defender Firewall with Advanced Security
1. In the same or linked GPO, navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Windows Defender Firewall with Advanced Security\Windows Defender Firewall with Advanced Security - [LDAP Path]\Inbound Rules`
2. Create a new custom Inbound Rule:
   * **Rule Type**: `Port`
   * **Protocol and Ports**: `TCP`, Specific local ports: `24158`
   * **Action**: `Allow the connection`
   * **Profile**: Check `Domain` and `Private` (uncheck `Public`)
   * **Name**: `AD-Hardening-WMI-StaticPort-In`
   * **Description**: `Permits inbound WMI traffic on dedicated static TCP port 24158 from authorized Tier 1 / PAW management subnets.`
3. Open the properties of `AD-Hardening-WMI-StaticPort-In` and navigate to the **Scope** tab:
   * Under **Remote IP address**, select **These IP addresses**.
   * Add the specific IP subnets of authorized PAWs, Tier 1 management bastions, and centralized SIEM/monitoring collectors. Do **not** leave this set to *Any IP address*.
4. Verify or create an inbound rule for the **RPC Endpoint Mapper**:
   * Protocol: `TCP`, Port: `135`
   * Scope: Restrict remote IP addresses strictly to the same authorized management subnets.
5. Disable generic dynamic WMI rules:
   * Ensure the predefined rule group `Windows Management Instrumentation (WMI)` is **not** enabled broadly, or set explicit block rules for dynamic high ports `49152-65535` from non-management subnets.

#### 3. Host Maintenance Reboot
Deploy the GPO to the target Organizational Unit (OU) and plan a host reboot during the next maintenance window to initialize the standalone host process cleanly.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following scripts locally to apply the WMI static port configuration and host firewall restrictions.

#### Remediation Script:
[Download Script: Set-WMIStaticPort.ps1](implementation_scripts/Set-WMIStaticPort.ps1)

```powershell
# Set-WMIStaticPort.ps1
# Description: Configures WMI to run in a standalone host process on static TCP port 24158 with packet privacy and configures host firewall rules.
# Target Engine: Windows PowerShell 5.1

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string[]]$ManagementSubnets = @()
)

Write-Host "Applying hardening requirement: Configure WMI Static Port and Service Hardening..." -ForegroundColor Cyan

# 1. Configure the static TCP port 24158 for WMI AppID
$WmiAppIdPath = "HKLM:\SOFTWARE\Classes\AppID\{8BC3F05E-D86B-11D0-A075-00C04FB68820}"
if (-not (Test-Path -Path $WmiAppIdPath)) {
    New-Item -Path $WmiAppIdPath -Force | Out-Null
}

Set-ItemProperty -Path $WmiAppIdPath -Name "Endpoints" -Value @("ncacn_ip_tcp,0,24158") -Type MultiString
Write-Host "[+] Configured WMI AppID static endpoint to TCP 24158." -ForegroundColor Green

# 2. Configure DCOM Authentication Level to Packet Privacy (6)
Set-ItemProperty -Path $WmiAppIdPath -Name "AuthenticationLevel" -Value 6 -Type DWord
Write-Host "[+] Configured WMI AppID DCOM authentication level to 6 (RPC_C_AUTHN_LEVEL_PKT_PRIVACY)." -ForegroundColor Green

# 3. Configure WMI service execution type to Standalone Host (Type = 16 / SERVICE_WIN32_OWN_PROCESS)
$WinmgmtSvcPath = "HKLM:\SYSTEM\CurrentControlSet\Services\winmgmt"
if (-not (Test-Path -Path $WinmgmtSvcPath)) {
    New-Item -Path $WinmgmtSvcPath -Force | Out-Null
}
Set-ItemProperty -Path $WinmgmtSvcPath -Name "Type" -Value 16 -Type DWord
Write-Host "[+] Configured WMI service execution type to 16 (SERVICE_WIN32_OWN_PROCESS)." -ForegroundColor Green

# 4. Invoke winmgmt standalone host configuration command
Write-Host "[+] Executing winmgmt.exe /standalonehost 6..." -ForegroundColor Gray
$Proc = Start-Process -FilePath "winmgmt.exe" -ArgumentList "/standalonehost 6" -Wait -NoNewWindow -PassThru

if ($Proc.ExitCode -eq 0) {
    Write-Host "[+] WMI standalone host command completed successfully." -ForegroundColor Green
} else {
    Write-Warning "[-] WMI standalone host command exited with code $($Proc.ExitCode)."
}

# 5. Configure Windows Defender Firewall Inbound Rule for WMI Static Port 24158
Write-Host "[+] Configuring Windows Defender Firewall rule for static TCP port 24158..." -ForegroundColor Gray
$RuleName = "AD-Hardening-WMI-StaticPort-In"
$ExistingRule = Get-NetFirewallRule -Name $RuleName -ErrorAction SilentlyContinue

$FirewallParams = @{
    DisplayName = "Active Directory Hardening - WMI Static Port (TCP 24158)"
    Description = "Permits inbound DCOM/WMI traffic on dedicated static TCP port 24158 from authorized management hosts."
    Direction   = "Inbound"
    Action      = "Allow"
    Protocol    = "TCP"
    LocalPort   = "24158"
    Profile     = "Domain,Private"
    Enabled     = "True"
}

if ($ManagementSubnets.Count -gt 0) {
    $FirewallParams["RemoteAddress"] = $ManagementSubnets
}

if ($ExistingRule) {
    Set-NetFirewallRule -Name $RuleName @FirewallParams | Out-Null
    Write-Host "[+] Updated existing firewall rule: $RuleName." -ForegroundColor Green
} else {
    New-NetFirewallRule -Name $RuleName @FirewallParams | Out-Null
    Write-Host "[+] Created new inbound firewall rule: $RuleName." -ForegroundColor Green
}

# 6. Disable unconstrained dynamic WMI inbound rules to prevent ephemeral port exposure
Write-Host "[+] Disabling built-in dynamic WMI firewall rules..." -ForegroundColor Gray
$DynamicWmiRules = Get-NetFirewallRule -DisplayGroup "Windows Management Instrumentation (WMI)" -ErrorAction SilentlyContinue |
    Where-Object { $_.Direction -eq "Inbound" -and $_.Name -like "*WMI-In*" -and $_.Name -ne $RuleName }

foreach ($DynRule in $DynamicWmiRules) {
    Disable-NetFirewallRule -Name $DynRule.Name | Out-Null
    Write-Host "    - Disabled dynamic WMI rule: $($DynRule.DisplayName)" -ForegroundColor Gray
}

Write-Host "`n[+] Hardening configuration applied successfully." -ForegroundColor Cyan
Write-Host "[!] IMPORTANT: A system reboot is strongly recommended to cleanly apply WMI service isolation and restart all dependent infrastructure services." -ForegroundColor Yellow
```

#### Audit Script:
[Download Script: Test-WMIStaticPort.ps1](audit_scripts/Test-WMIStaticPort.ps1)

```powershell
# Test-WMIStaticPort.ps1
# Description: Audits WMI static port registry configuration, DCOM authentication level, service isolation, and firewall rules.
# Target Engine: Windows PowerShell 5.1

Write-Host "Auditing WMI static port configuration and service hardening..." -ForegroundColor Cyan
$vulnerable = $false

# 1. Audit AppID Endpoints Registry Setting
$WmiAppIdPath = "HKLM:\SOFTWARE\Classes\AppID\{8BC3F05E-D86B-11D0-A075-00C04FB68820}"
$AppIdProps = Get-ItemProperty -Path $WmiAppIdPath -ErrorAction SilentlyContinue

if ($AppIdProps -and $AppIdProps.Endpoints) {
    $Endpoints = $AppIdProps.Endpoints
    if ($Endpoints -contains "ncacn_ip_tcp,0,24158") {
        Write-Host "[+] WMI static port registry endpoint is configured correctly (TCP 24158)." -ForegroundColor Green
    } else {
        Write-Host "[!] NON-COMPLIANT: WMI Endpoints registry value is: '$($Endpoints -join ', ')' (Expected: 'ncacn_ip_tcp,0,24158')" -ForegroundColor Red
        $vulnerable = $true
    }
} else {
    Write-Host "[!] NON-COMPLIANT: WMI AppID 'Endpoints' registry value is missing or inaccessible." -ForegroundColor Red
    $vulnerable = $true
}

# 2. Audit AppID DCOM Authentication Level (Packet Privacy = 6)
if ($AppIdProps -and $null -ne $AppIdProps.AuthenticationLevel) {
    $AuthLevel = [int]$AppIdProps.AuthenticationLevel
    if ($AuthLevel -ge 6) {
        Write-Host "[+] WMI AppID DCOM AuthenticationLevel is configured to Packet Privacy ($AuthLevel)." -ForegroundColor Green
    } else {
        Write-Host "[!] NON-COMPLIANT: WMI AppID AuthenticationLevel is: $AuthLevel (Expected: 6 [RPC_C_AUTHN_LEVEL_PKT_PRIVACY])" -ForegroundColor Red
        $vulnerable = $true
    }
} else {
    Write-Host "[!] NON-COMPLIANT: WMI AppID 'AuthenticationLevel' value is missing (Expected: 6)." -ForegroundColor Red
    $vulnerable = $true
}

# 3. Audit WMI Service Execution Type (Standalone Host = 16)
$WinmgmtPath = "HKLM:\SYSTEM\CurrentControlSet\Services\winmgmt"
$TypeVal = Get-ItemProperty -Path $WinmgmtPath -Name "Type" -ErrorAction SilentlyContinue

if ($TypeVal -and $null -ne $TypeVal.Type) {
    $Type = [int]$TypeVal.Type
    if ($Type -eq 16) {
        Write-Host "[+] WMI is configured to run as a standalone process (Type = 16 [SERVICE_WIN32_OWN_PROCESS])." -ForegroundColor Green
    } else {
        Write-Host "[!] NON-COMPLIANT: WMI service execution type is: $Type (Expected: 16 [SERVICE_WIN32_OWN_PROCESS])" -ForegroundColor Red
        $vulnerable = $true
    }
} else {
    Write-Host "[!] NON-COMPLIANT: WMI service registry key is missing or inaccessible." -ForegroundColor Red
    $vulnerable = $true
}

# 4. Audit Host Firewall Inbound Rule for TCP 24158
$FwRules = Get-NetFirewallRule -Direction Inbound -Enabled True -ErrorAction SilentlyContinue |
    Where-Object { $_.Action -eq "Allow" }

$WmiStaticPortAllowed = $false
foreach ($Rule in $FwRules) {
    $PortFilter = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $Rule -ErrorAction SilentlyContinue
    if ($PortFilter -and $PortFilter.Protocol -eq "TCP") {
        $LocalPorts = @($PortFilter.LocalPort)
        if ($LocalPorts -contains "24158") {
            $WmiStaticPortAllowed = $true
            break
        }
    }
}

if ($WmiStaticPortAllowed) {
    Write-Host "[+] Windows Defender Firewall has an active inbound allow rule for TCP port 24158." -ForegroundColor Green
} else {
    Write-Host "[!] NON-COMPLIANT: No active inbound firewall rule permitting TCP port 24158 found." -ForegroundColor Red
    $vulnerable = $true
}

# 5. Audit Built-in Dynamic WMI Firewall Rules
$DynamicWmiRules = Get-NetFirewallRule -DisplayGroup "Windows Management Instrumentation (WMI)" -Direction Inbound -Enabled True -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -like "*WMI-In*" }

if ($DynamicWmiRules) {
    $UnrestrictedDynamicRule = $false
    foreach ($DynRule in $DynamicWmiRules) {
        $AddressFilter = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $DynRule -ErrorAction SilentlyContinue
        if ($AddressFilter -and ($AddressFilter.RemoteAddress -contains "Any" -or -not $AddressFilter.RemoteAddress)) {
            $UnrestrictedDynamicRule = $true
            break
        }
    }
    if ($UnrestrictedDynamicRule) {
        Write-Host "[!] NON-COMPLIANT: Built-in dynamic WMI firewall rules are enabled and allow unconstrained dynamic RPC ports from Any address." -ForegroundColor Red
        $vulnerable = $true
    } else {
        Write-Host "[+] Built-in dynamic WMI firewall rules are restricted to specific subnets." -ForegroundColor Green
    }
} else {
    Write-Host "[+] Built-in generic dynamic WMI inbound firewall rules are disabled." -ForegroundColor Green
}

# Final Verdict
if ($vulnerable) {
    Write-Host "Audit result: NON-COMPLIANT" -ForegroundColor Red
} else {
    Write-Host "Audit result: COMPLIANT" -ForegroundColor Green
}
```

---

## Sources & Compliance References
* **ANSSI AD Hardening Guide**:
  * Recommendation R7: Filtering and IPsec on Domain Controllers
  * Recommendation R8: Administration network subnets / filtering rules
* **CIS Windows Server Benchmark**:
  * Section 19: Windows Defender Firewall with Advanced Security
* **Microsoft Security Guidance & Architecture**:
  * [Setting Up a Fixed Port for WMI](https://learn.microsoft.com/en-us/windows/win32/wmisdk/setting-up-a-fixed-port-for-wmi)
  * [KB5004442 / CVE-2021-26414: Manage changes for Windows DCOM Server Security Feature Bypass](https://support.microsoft.com/en-us/topic/kb5004442-manage-changes-for-windows-dcom-server-security-feature-bypass-cve-2021-26414-f1400b52-c141-43d2-941e-37ed901c769c)
* **DSInternals AD Firewall Guide (Michael Grafnetter)**:
  * [Active Directory Firewall - Domain Controller Firewall](https://firewall.dsinternals.com/ADDS/)
* **MITRE ATT&CK Framework**:
  * [T1047: Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047/)
  * [T1021.002: Remote Services: SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002/)
  * [T1040: Network Sniffing](https://attack.mitre.org/techniques/T1040/)
