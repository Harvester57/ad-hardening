# [REQ-PAW-022] Disable Incoming Remote Desktop Access for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration.
* **Operating Systems**: Windows 10 Enterprise (1607+) and Windows 11 Enterprise.

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **GPO Paths**:
    * `Computer Configuration\Administrative Templates\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Connections`
    * `Computer Configuration\Administrative Templates\System\Remote Assistance`
  * **Registry Locations**:
    * `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server`
      * `fDenyTSConnections` = `1` (REG_DWORD, Disabled)
      * `fAllowToGetHelp` = `0` (REG_DWORD, Solicited Remote Assistance Disabled)
    * `HKLM\SOFTWARE\Policies\Microsoft\WindowsNT\Terminal Services`
      * `fAllowToGetHelp` = `0` (REG_DWORD, Solicited Remote Assistance Policy Disabled)

---

## Rationale
Remote Desktop Protocol (RDP) is one of the primary mechanisms used by attackers for lateral movement and administrative session hijacking.

For Privileged Access Workstations (PAWs), which manage Tier 0 administrative assets:
1. **Lateral Movement Prevention**: PAWs represent physical console endpoints used to administer the forest. They must never accept inbound network connections. Disabling incoming RDP connections prevents attackers from pivoting from compromised general workstations to the PAW.
2. **Session Security**: Eliminating RDP listener ports prevents credential sniffing, password spraying, and remote exploitation of remote desktop services vulnerabilities on the administrative root of trust.
3. **Remote Assistance Block**: Disabling solicited remote assistance prevents potential remote command execution or remote support hijacking.

---

## Legacy Impact & Compatibility
* **No Remote Administration**: Support technicians cannot connect to PAWs via RDP. All operations on a PAW must be performed directly at the physical console.
* **User Assistance**: Support sessions cannot be initiated via Remote Desktop or Remote Assistance. Local diagnostic procedures must be used.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

#### 1. Disable Inbound Remote Desktop Connections
1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the PAW GPO (e.g., `GPO_Hardening_PAW`).
3. Navigate to:
   `Computer Configuration\Administrative Templates\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Connections`
4. Configure the setting:
   * **Policy**: `Allow users to connect remotely by using Remote Desktop Services`
   * **Setting**: `Disabled`

#### 2. Disable Solicited Remote Assistance
1. Navigate to:
   `Computer Configuration\Administrative Templates\System\Remote Assistance`
2. Configure the setting:
   * **Policy**: `Configure Solicited Remote Assistance`
   * **Setting**: `Disabled`

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following scripts locally to disable Remote Desktop and Remote Assistance, and enforce NLA and secure registry keys.

[Download Script: Disable-PawRemoteDesktop.ps1](implementation_scripts/Disable-PawRemoteDesktop.ps1)

```powershell
# Disable-PawRemoteDesktop.ps1
# Description: Disables Remote Desktop and Solicited Remote Assistance connections, sets NLA requirements, and cleans parameters on PAWs.

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

*To audit Remote Desktop and Remote Assistance status on the PAW:*

[Download Script: Test-PawRemoteDesktopStatus.ps1](audit_scripts/Test-PawRemoteDesktopStatus.ps1)

```powershell
# Test-PawRemoteDesktopStatus.ps1
# Description: Audits local RDP, Remote Assistance, security layer, temp folders, and NLA registry configuration and listening firewall ports on PAWs.

Write-Host "--- Auditing Remote Desktop Configuration ---" -ForegroundColor Cyan

$RdpPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"
$RdpSecPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
$TSPoliciesPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"

$DenyTS = Get-ItemProperty -Path $RdpPath -Name "fDenyTSConnections" -ErrorAction SilentlyContinue
$DenyVal = if ($DenyTS) { $DenyTS.fDenyTSConnections } else { 1 }

$NlaProp = Get-ItemProperty -Path $RdpSecPath -Name "UserAuthentication" -ErrorAction SilentlyContinue
$NlaVal = if ($NlaProp) { $NlaProp.UserAuthentication } else { 0 }

$DenyColor = if ($DenyVal -eq 1) { "Green" } else { "Red" }
$NlaColor = if ($NlaVal -eq 1) { "Green" } else { "Red" }

Write-Host "    - fDenyTSConnections: $DenyVal (Required = 1 to block all)" -ForegroundColor $DenyColor
Write-Host "    - UserAuthentication (NLA): $NlaVal (Required = 1 if RDP is enabled)" -ForegroundColor $NlaColor

# Check if port 3389 firewall rule is active and enabled
$RdpFirewall = Get-NetFirewallRule -Name "RemoteDesktop-UserMode-In-TCP" -ErrorAction SilentlyContinue
if ($RdpFirewall) {
    $FirewallColor = if ($RdpFirewall.Enabled -eq $true) { "Red" } else { "Green" }
    Write-Host "    - RDP Inbound Firewall Rule Active: $($RdpFirewall.Enabled) (Expected = False)" -ForegroundColor $FirewallColor
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

## Sources & Compliance References
* **CIS Microsoft Windows 10 Benchmark**: Section 18.2.1 (Require user authentication for remote connections by using Network Level Authentication)
* **ANSSI AD Hardening Guide**: Security guidelines regarding Remote Desktop access and management protocols on administrative systems.
* **DoD Windows 11 STIG**: Solicited Remote Assistance requirements.
