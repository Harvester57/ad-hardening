# Configure-DisablePrintSpooler.ps1
# Description: Stops and disables the Print Spooler service.

Write-Host "Applying hardening requirement: Disable Print Spooler..." -ForegroundColor Cyan

$serviceName = "Spooler"
$service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue

if ($service) {
    if ($service.Status -eq "Running") {
        Write-Host "Stopping service $($serviceName)..." -ForegroundColor Gray
        Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
    }
    
    # Configure startup type to disabled
    Set-Service -Name $serviceName -StartupType Disabled
    Write-Host "Service $($serviceName) has been stopped and disabled." -ForegroundColor Green
} else {
    Write-Host "Service $($serviceName) not found." -ForegroundColor Yellow
}
