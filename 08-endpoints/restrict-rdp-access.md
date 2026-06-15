# [REQ-END-005] Restrict Remote Desktop Access

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers.
* **Operating Systems**: Windows 10 (and above) Enterprise/Professional, Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **GPO Paths**:
    * `Computer Configuration\Administrative Templates\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Connections`
    * `Computer Configuration\Administrative Templates\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Security`
    * `Computer Configuration\Administrative Templates\System\Remote Assistance`
  * **Registry Locations**:
    * `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server`
      * `fDenyTSConnections` = `1` (REG_DWORD, Disabled)
    * `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp`
      * `UserAuthentication` = `1` (REG_DWORD, NLA Enabled)
    * `HKLM\SOFTWARE\Policies\Microsoft\WindowsNT\Terminal Services`
      * `fAllowToGetHelp` = `0` (REG_DWORD, Solicited Remote Assistance Disabled)
      * `MaxTicketExpiryUnits` = (Delete / Not Configured)
      * `MaxTicketExpiry` = (Delete / Not Configured)
      * `fUseMailto` = (Delete / Not Configured)
      * `fAllowFullControl` = (Delete / Not Configured)

---

## Rationale
Remote Desktop Protocol (RDP) is one of the primary mechanisms used by attackers for lateral movement and administrative session hijacking. If inbound RDP is enabled globally on workstations:
1. **Lateral Movement**: An attacker who compromises a single standard user's credentials with administrative permissions on other machines can RDP from workstation to workstation across the network.
2. **Session Hijacking**: Attackers can hijack existing administrative RDP sessions using built-in command-line tools (such as `tscon.exe`) if they obtain administrator privileges on the system.
3. **Password Spraying**: Open RDP ports allow attackers to attempt password spraying or brute-force attacks against local administrative accounts.

Furthermore, Windows **Remote Assistance** allows helper connections that can lead to remote code execution or unauthorized access if not properly restricted. Disabling Solicited Remote Assistance and removing any legacy configuration values limits the workstation's attack surface.

The safest configuration is to disable Remote Desktop Services and Remote Assistance entirely on all Tier 2 workstations. If RDP is strictly necessary for remote technical support, it must require Network Level Authentication (NLA) and the listening firewall rules must restrict access to authorized management subnets only.

---

## Legacy Impact & Compatibility
* **Remote Administration**: Support technicians cannot connect to workstations via RDP unless they connect from an IP address inside the authorized administrative subnet (e.g., from a PAW or Jump Host).
* **User Assistance**: Standard users cannot use Remote Desktop or Remote Assistance to share screens or assist one another. Alternate secure remote assistance tools (which require local user approval and do not open listener ports) must be used.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

#### 1. Disable Inbound Remote Desktop Connections (Default Hardening)
1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Create or edit a GPO linked to the workstations OU (e.g., `GPO_Hardening_Workstations`).
3. Navigate to:
   `Computer Configuration\Administrative Templates\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Connections`
4. Configure the setting:
   * **Policy**: `Allow users to connect remotely by using Remote Desktop Services`
   * **Setting**: `Disabled`

#### 2. Enforce NLA and High Encryption (If RDP is Required for Admins)
If RDP is strictly required, enable it but restrict it using the following settings:
1. Under the same path:
   * **Policy**: `Allow users to connect remotely by using Remote Desktop Services` -> `Enabled`
2. Navigate to:
   `Computer Configuration\Administrative Templates\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Security`
3. Configure the following settings:
   * **Policy**: `Require user authentication for remote connections by using Network Level Authentication`
   * **Setting**: `Enabled`
   * **Policy**: `Set client connection encryption level`
   * **Setting**: `Enabled` (Select `High Level` in the options dropdown)
   * **Policy**: `Require use of specific security layer for remote (RDP) connections`
   * **Setting**: `Enabled: SSL`
4. Deploy local firewall rules via GPO to restrict TCP port 3389 inbound to administrative subnet ranges only.

#### 3. Configure Temporary Folders Deletion on Exit
1. Navigate to:
   `Computer Configuration\Administrative Templates\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Temporary Folders`
2. Configure the setting:
   * **Policy**: `Do not delete temp folders upon exit`
   * **Setting**: `Disabled` (ensures session temporary directories are deleted when users log off)

#### 4. Disable Solicited Remote Assistance
1. Navigate to:
   `Computer Configuration\Administrative Templates\System\Remote Assistance`
2. Configure the setting:
   * **Policy**: `Configure Solicited Remote Assistance`
   * **Setting**: `Disabled`

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following scripts locally to disable Remote Desktop and Remote Assistance, and enforce NLA and secure registry keys.

[Download Script: Disable-RemoteDesktop.ps1](implementation_scripts/Disable-RemoteDesktop.ps1)

```powershell
# Disable-RemoteDesktop.ps1
# Disables Remote Desktop and Solicited Remote Assistance connections, sets NLA requirements, sets Security Layer to SSL, configures temp folder deletion, and cleans parameters.

Write-Host "--- Restricting Remote Desktop and Remote Assistance Access ---" -ForegroundColor Cyan

$RdpPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"

# 1. Disable RDP Connections (fDenyTSConnections = 1)
Set-ItemProperty -Path $RdpPath -Name "fDenyTSConnections" -Value 1 -Type DWord -Force
Write-Host "[+] Inbound Remote Desktop connections disabled." -ForegroundColor Green

# 2. Enforce Network Level Authentication (UserAuthentication = 1)
$RdpSecPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
if (Test-Path $RdpSecPath) {
    Set-ItemProperty -Path $RdpSecPath -Name "UserAuthentication" -Value 1 -Type DWord -Force
    Write-Host "[+] Network Level Authentication (NLA) enforced." -ForegroundColor Green
}

# 3. Disable Remote Assistance (fAllowToGetHelp = 0)
Set-ItemProperty -Path $RdpPath -Name "fAllowToGetHelp" -Value 0 -Type DWord -Force

# 4. Disable and clean Solicited Remote Assistance Policies, set SSL, and delete temp folders
$TSPoliciesPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
if (-not (Test-Path $TSPoliciesPath)) {
    New-Item -Path $TSPoliciesPath -Force | Out-Null
}
Set-ItemProperty -Path $TSPoliciesPath -Name "fAllowToGetHelp" -Value 0 -Type DWord -Force
Set-ItemProperty -Path $TSPoliciesPath -Name "SecurityLayer" -Value 2 -Type DWord -Force
Set-ItemProperty -Path $TSPoliciesPath -Name "DeleteTempDirsOnExit" -Value 1 -Type DWord -Force

$ParamsToDelete = @("MaxTicketExpiryUnits", "MaxTicketExpiry", "fUseMailto", "fAllowFullControl")
foreach ($Param in $ParamsToDelete) {
    if (Get-ItemProperty -Path $TSPoliciesPath -Name $Param -ErrorAction SilentlyContinue) {
        Remove-ItemProperty -Path $TSPoliciesPath -Name $Param -Force -ErrorAction SilentlyContinue
    }
}
Write-Host "[+] Remote Desktop policies (SSL, Temp folders, Solicited Help) configured and cleaned." -ForegroundColor Green
```

*To audit Remote Desktop and Remote Assistance status:*
[Download Script: Test-RemoteDesktopStatus.ps1](audit_scripts/Test-RemoteDesktopStatus.ps1)

```powershell
# Test-RemoteDesktopStatus.ps1
# Audits local RDP, Remote Assistance, security layer, temp folders, and NLA registry configuration and listening firewall ports.

Write-Host "--- Auditing Remote Desktop Configuration ---" -ForegroundColor Cyan

$RdpPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"
$RdpSecPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
$TSPoliciesPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"

$DenyTS = Get-ItemProperty -Path $RdpPath -Name "fDenyTSConnections" -ErrorAction SilentlyContinue
$DenyVal = if ($DenyTS) { $DenyTS.fDenyTSConnections } else { 1 }

$NlaProp = Get-ItemProperty -Path $RdpSecPath -Name "UserAuthentication" -ErrorAction SilentlyContinue
$NlaVal = if ($NlaProp) { $NlaProp.UserAuthentication } else { 0 }

$DenyColor = if ($DenyVal -eq 1) { "Green" } else { "Yellow" }
$NlaColor = if ($NlaVal -eq 1) { "Green" } else { "Red" }

Write-Host "    - fDenyTSConnections: $DenyVal (Recommended = 1 to block all)" -ForegroundColor $DenyColor
Write-Host "    - UserAuthentication (NLA): $NlaVal (Required = 1 if RDP is enabled)" -ForegroundColor $NlaColor

# Check if port 3389 firewall rule is active and enabled
$RdpFirewall = Get-NetFirewallRule -Name "RemoteDesktop-UserMode-In-TCP" -ErrorAction SilentlyContinue
if ($RdpFirewall) {
    $FirewallColor = if ($RdpFirewall.Enabled -eq $true) { "Yellow" } else { "Green" }
    Write-Host "    - RDP Inbound Firewall Rule Active: $($RdpFirewall.Enabled)" -ForegroundColor $FirewallColor
}

# Audit Remote Assistance
$GetHelpTS = Get-ItemProperty -Path $RdpPath -Name "fAllowToGetHelp" -ErrorAction SilentlyContinue
$GetHelpTSVal = if ($GetHelpTS) { $GetHelpTS.fAllowToGetHelp } else { 0 }
$HelpColor = if ($GetHelpTSVal -eq 0) { "Green" } else { "Red" }
Write-Host "    - fAllowToGetHelp (Terminal Server): $GetHelpTSVal (Recommended = 0)" -ForegroundColor $HelpColor

# Audit Solicited Remote Assistance Policy, Security Layer, and Temp Folders
if (Test-Path $TSPoliciesPath) {
    $PolGetHelp = Get-ItemProperty -Path $TSPoliciesPath -Name "fAllowToGetHelp" -ErrorAction SilentlyContinue
    $PolGetHelpVal = if ($PolGetHelp) { $PolGetHelp.fAllowToGetHelp } else { $null }
    
    $PolHelpColor = if ($PolGetHelpVal -eq 0) { "Green" } else { "Red" }
    Write-Host "    - fAllowToGetHelp (Policies): $PolGetHelpVal (Recommended = 0)" -ForegroundColor $PolHelpColor
    
    $SecurityLayerProp = Get-ItemProperty -Path $TSPoliciesPath -Name "SecurityLayer" -ErrorAction SilentlyContinue
    $SecurityLayerVal = if ($SecurityLayerProp) { $SecurityLayerProp.SecurityLayer } else { $null }
    $SecLayerColor = if ($SecurityLayerVal -eq 2) { "Green" } else { "Red" }
    Write-Host "    - SecurityLayer (SSL): $SecurityLayerVal (Required = 2)" -ForegroundColor $SecLayerColor

    $DeleteTempProp = Get-ItemProperty -Path $TSPoliciesPath -Name "DeleteTempDirsOnExit" -ErrorAction SilentlyContinue
    $DeleteTempVal = if ($DeleteTempProp) { $DeleteTempProp.DeleteTempDirsOnExit } else { $null }
    $DeleteTempColor = if ($DeleteTempVal -eq 1) { "Green" } else { "Red" }
    Write-Host "    - DeleteTempDirsOnExit (Temp Folders): $DeleteTempVal (Required = 1)" -ForegroundColor $DeleteTempColor

    $Params = @("MaxTicketExpiryUnits", "MaxTicketExpiry", "fUseMailto", "fAllowFullControl")
    foreach ($Param in $Params) {
        $Val = (Get-ItemProperty -Path $TSPoliciesPath -Name $Param -ErrorAction SilentlyContinue).$Param
        if ($null -ne $Val) {
            Write-Host "    - VULNERABLE: Solicited Remote Assistance parameter '$Param' is set to '$Val' (Expected: Deleted/Not Configured)" -ForegroundColor Red
        } else {
            Write-Host "    - Parameter '$Param': Not Configured (Correct)" -ForegroundColor Green
        }
    }
} else {
    Write-Host "    - Solicited Remote Assistance Policy Path does not exist" -ForegroundColor Red
}
```

---

## 🔗 Sources & Compliance References
* **CIS Microsoft Windows 10 Benchmark**: Section 18.2.1 (Require user authentication for remote connections by using Network Level Authentication)
* **ANSSI AD Hardening Guide**: Security guidelines regarding Remote Desktop access and management protocols.
* **DoD Windows 11 STIG**: Solicited Remote Assistance requirements.
