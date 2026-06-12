# Disable-RemoteDesktop.ps1
# Disables Remote Desktop and Solicited Remote Assistance connections, sets NLA requirements, and cleans parameters.

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

# 4. Disable and clean Solicited Remote Assistance Policies
$TSPoliciesPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsNT\Terminal Services"
if (-not (Test-Path $TSPoliciesPath)) {
    New-Item -Path $TSPoliciesPath -Force | Out-Null
}
Set-ItemProperty -Path $TSPoliciesPath -Name "fAllowToGetHelp" -Value 0 -Type DWord -Force

$ParamsToDelete = @("MaxTicketExpiryUnits", "MaxTicketExpiry", "fUseMailto", "fAllowFullControl")
foreach ($Param in $ParamsToDelete) {
    if (Get-ItemProperty -Path $TSPoliciesPath -Name $Param -ErrorAction SilentlyContinue) {
        Remove-ItemProperty -Path $TSPoliciesPath -Name $Param -Force -ErrorAction SilentlyContinue
    }
}
Write-Host "[+] Solicited Remote Assistance policies disabled and cleaned." -ForegroundColor Green
