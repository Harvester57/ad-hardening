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
