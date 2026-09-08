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
