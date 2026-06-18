# Set-PAWSmartCardEnforcement.ps1
# Description: Configures the registry to require smart cards for interactive logons on PAWs.
# Target Engine: Windows PowerShell 5.1

Write-Host "Enforcing smart card interactive logon requirement..." -ForegroundColor Cyan

$RegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$ValueName = "ScForceOption"
$ValueData = 1

if (-not (Test-Path $RegPath)) {
    New-Item -Path $RegPath -Force | Out-Null
}

Set-ItemProperty -Path $RegPath -Name $ValueName -Value $ValueData -Type DWord -Force
Write-Host "Smart card interactive logon requirement applied successfully." -ForegroundColor Green
