# Hardening Requirement: Restrict Remote Desktop Access

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers.
* **Operating Systems**: Windows 10 (and above) Enterprise/Professional, Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * Computer Configuration\Administrative Templates\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Connections
  * Computer Configuration\Administrative Templates\Windows Components\Remote Desktop Services\Remote Desktop Session Host\Security
  * HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server

---

## Rationale
Remote Desktop Protocol (RDP) is one of the primary mechanisms used by attackers for lateral movement and administrative session hijacking. If inbound RDP is enabled globally on workstations:
1. **Lateral Movement**: An attacker who compromises a single standard user's credentials with administrative permissions on other machines can RDP from workstation to workstation across the network.
2. **Session Hijacking**: Attackers can hijack existing administrative RDP sessions using built-in command-line tools (such as `tscon.exe`) if they obtain administrator privileges on the system.
3. **Password Spraying**: Open RDP ports allow attackers to attempt password spraying or brute-force attacks against local administrative accounts.

The safest configuration is to disable Remote Desktop Services entirely on all Tier 2 workstations. If RDP is strictly necessary for remote technical support, it must require Network Level Authentication (NLA) and the listening firewall rules must restrict access to authorized management subnets only.

---

## Legacy Impact & Compatibility
* **Remote Administration**: Support technicians cannot connect to workstations via RDP unless they connect from an IP address inside the authorized administrative subnet (e.g., from a PAW or Jump Host).
* **User Assistance**: Standard users cannot use Remote Desktop to share screens or assist one another. Alternate secure remote assistance tools (which require local user approval and do not open listener ports) must be used.

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
4. Deploy local firewall rules via GPO to restrict TCP port 3389 inbound to administrative subnet ranges only.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following scripts locally to disable Remote Desktop or enforce NLA and secure registry keys.

[Download Script: Disable-RemoteDesktop.ps1](implementation_scripts/Disable-RemoteDesktop.ps1)

```powershell
# Disable-RemoteDesktop.ps1
# Disables Remote Desktop connection requests and sets NLA requirements locally.

Write-Host "--- Restricting Remote Desktop Access ---" -ForegroundColor Cyan

$RdpPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"

# 1. Disable RDP Connections (fDenyTSConnections = 1)
Set-ItemProperty -Path $RdpPath -Name "fDenyTSConnections" -Value 1 -Type DWord
Write-Host "[+] Inbound Remote Desktop connections disabled." -ForegroundColor Green

# 2. Enforce Network Level Authentication (UserAuthentication = 1)
$RdpSecPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
if (Test-Path $RdpSecPath) {
    Set-ItemProperty -Path $RdpSecPath -Name "UserAuthentication" -Value 1 -Type DWord
    Write-Host "[+] Network Level Authentication (NLA) enforced." -ForegroundColor Green
}

# 3. Disable Remote Assistance Connections
$RAPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"
Set-ItemProperty -Path $RAPath -Name "fAllowToGetHelp" -Value 0 -Type DWord
Write-Host "[+] Remote Assistance connection requests disabled." -ForegroundColor Green
```

*To audit Remote Desktop and NLA status:*
[Download Script: Test-RemoteDesktopStatus.ps1](audit_scripts/Test-RemoteDesktopStatus.ps1)

```powershell
# Test-RemoteDesktopStatus.ps1
# Audits local RDP registry configuration and listening firewall ports.

Write-Host "--- Auditing Remote Desktop Configuration ---" -ForegroundColor Cyan

$RdpPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"
$RdpSecPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"

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
```

---

## 🔗 Sources & Compliance References
* **CIS Microsoft Windows 10 Benchmark**: Section 18.2.1 (Require user authentication for remote connections by using Network Level Authentication)
* **ANSSI AD Hardening Guide**: Security guidelines regarding Remote Desktop access and management protocols.
