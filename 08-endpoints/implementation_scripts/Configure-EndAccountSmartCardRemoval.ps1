# Configure-EndAccountSmartCardRemoval.ps1
# Description: Configures Smart Card removal behavior to Lock Workstation and enables SCPolicySvc on Endpoints.

Write-Host "Configuring Endpoint Smart Card removal behavior..." -ForegroundColor Cyan

# 1. Configure Winlogon ScRemoveOption
$WinlogonPath = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
if (-not (Test-Path $WinlogonPath)) {
    New-Item -Path $WinlogonPath -Force | Out-Null
}
Set-ItemProperty -Path $WinlogonPath -Name "ScRemoveOption" -Value "1" -Type String -Force

# 2. Ensure Smart Card Removal Policy service is configured for Automatic start
$ServiceName = "SCPolicySvc"
$Service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($null -ne $Service) {
    Set-Service -Name $ServiceName -StartupType Automatic
    if ($Service.Status -ne "Running") {
        Start-Service -Name $ServiceName -ErrorAction SilentlyContinue
    }
}

Write-Host "Smart card removal behavior set to Lock Workstation ('1') and service configured." -ForegroundColor Green
