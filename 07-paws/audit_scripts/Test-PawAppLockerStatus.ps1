# Test-PawAppLockerStatus.ps1
# Description: Checks the current configuration and operational status of the Application Identity service.

Write-Host "--- Auditing AppLocker Service Status ---" -ForegroundColor Cyan

$AppIDSvc = Get-Service -Name AppIDSvc -ErrorAction SilentlyContinue

if ($AppIDSvc) {
    if ($AppIDSvc.Status -eq "Running" -and $AppIDSvc.StartType -eq "Automatic") {
        Write-Host "    - AppLocker Service Status: Running | Startup: Automatic (Secure)" -ForegroundColor Green
    } else {
        Write-Host "    - VULNERABLE: AppLocker Service Status: $($AppIDSvc.Status) | Startup: $($AppIDSvc.StartType) (Should be Running/Automatic)" -ForegroundColor Red
    }
} else {
    Write-Host "    - VULNERABLE: Application Identity Service (AppIDSvc) is not installed." -ForegroundColor Red
}
