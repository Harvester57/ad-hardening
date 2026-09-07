# Configure-DisablePeernet.ps1
# Description: Disables Microsoft Peer-to-Peer Networking Services policy on Domain Controllers.

Write-Host "Disabling Microsoft Peer-to-Peer Networking Services..." -ForegroundColor Cyan

$PeernetPath = "HKLM:\SOFTWARE\Policies\Microsoft\Peernet"
if (-not (Test-Path -Path $PeernetPath)) {
    New-Item -Path $PeernetPath -Force | Out-Null
}

Set-ItemProperty -Path $PeernetPath -Name "Disabled" -Value 1 -Type DWord -ErrorAction Stop

Write-Host "Microsoft Peer-to-Peer Networking Services disabled successfully (Disabled = 1)." -ForegroundColor Green
