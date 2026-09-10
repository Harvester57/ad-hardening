# Get-PawAccountSmartCardRemovalStatus.ps1
# Description: Audits Smart Card removal behavior and service status on PAWs.

Write-Host "--- Auditing PAW Smart Card Removal Behavior ---" -ForegroundColor Cyan

$WinlogonPath = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"

if (-not (Test-Path -Path $WinlogonPath)) {
    Write-Host "    [!] MISSING KEY: $WinlogonPath" -ForegroundColor Red
    Write-Output "Non-Compliant"
    exit 1
}

$Val = (Get-ItemProperty -Path $WinlogonPath -Name "ScRemoveOption" -ErrorAction SilentlyContinue).ScRemoveOption

if ($Val -eq "1") {
    Write-Host "    [+] ScRemoveOption is set to '$Val' (Lock Workstation - Secure)." -ForegroundColor Green
    Write-Output "Compliant"
    exit 0
} else {
    Write-Host "    [!] VULNERABLE: ScRemoveOption is set to '$Val' (Expected: '1')" -ForegroundColor Red
    Write-Output "Non-Compliant"
    exit 1
}
