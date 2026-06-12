# Configure-PawAppLockerService.ps1
# Description: Configures the Application Identity service (AppIDSvc) to start automatically and run.

Write-Host "Applying AppLocker Identity service hardening..." -ForegroundColor Cyan

$AppLockerService = Get-Service -Name AppIDSvc -ErrorAction SilentlyContinue

if ($AppLockerService) {
    Set-Service -Name AppIDSvc -StartupType Automatic
    Start-Service -Name AppIDSvc -ErrorAction SilentlyContinue
    Write-Host "[+] Application Identity Service (AppIDSvc) set to Automatic and started." -ForegroundColor Green
} else {
    Write-Warning "[-] Application Identity Service not found on this machine."
}
