# Test-RemoteDesktopStatus.ps1
# Audits local RDP, Remote Assistance, and NLA registry configuration and listening firewall ports.

Write-Host "--- Auditing Remote Desktop Configuration ---" -ForegroundColor Cyan

$RdpPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"
$RdpSecPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
$TSPoliciesPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsNT\Terminal Services"

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

# Audit Solicited Remote Assistance Policy
if (Test-Path $TSPoliciesPath) {
    $PolGetHelp = Get-ItemProperty -Path $TSPoliciesPath -Name "fAllowToGetHelp" -ErrorAction SilentlyContinue
    $PolGetHelpVal = if ($PolGetHelp) { $PolGetHelp.fAllowToGetHelp } else { $null }
    
    $PolHelpColor = if ($PolGetHelpVal -eq 0) { "Green" } else { "Red" }
    Write-Host "    - fAllowToGetHelp (Policies): $($PolGetHelpVal | Out-String).Trim() (Recommended = 0)" -ForegroundColor $PolHelpColor
    
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
    Write-Host "    - Solicited Remote Assistance Policy Path does not exist (Expected fAllowToGetHelp = 0)" -ForegroundColor Red
}
