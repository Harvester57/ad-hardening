# Configure-DisableUnnecessaryServices.ps1
# Description: Stops and disables unnecessary services on Domain Controllers.

Write-Host "Applying hardening requirement: Disable Unnecessary Services on Domain Controllers..." -ForegroundColor Cyan

$services = @(
    "XblAuthManager",
    "XblGameSave",
    "AxInstSV",
    "bthserv",
    "CDPUserSvc",
    "PimIndexMaintenanceSvc",
    "dmwappushservice",
    "MapsBroker",
    "lfsvc",
    "SharedAccess",
    "lltdsvc",
    "wlidsvc",
    "NgcSvc",
    "NgcCtnrSvc",
    "NcbService",
    "PhoneSvc",
    "PrintNotify",
    "PcaSvc",
    "QWAVE",
    "RmSvc",
    "SensorDataService",
    "SensrSvc",
    "SensorService",
    "ShellHWDetection",
    "ScDeviceEnum",
    "SSDPSRV",
    "WiaRpc",
    "OneSyncSvc",
    "upnphost",
    "UserDataSvc",
    "UnistoreSvc",
    "WalletService",
    "Audiosrv",
    "AudioEndpointBuilder",
    "FrameServer",
    "stisvc",
    "wisvc",
    "icssvc",
    "WpnService",
    "WpnUserService"
)

foreach ($serviceName in $services) {
    Write-Host "Processing service $($serviceName)..." -ForegroundColor Gray
    
    # Stop the service if it is running
    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($service) {
        if ($service.Status -eq "Running") {
            Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
            Write-Host "  Service $($serviceName) stopped." -ForegroundColor Gray
        }
    }

    # Disable the service startup in registry
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName"
    if (Test-Path $regPath) {
        Set-ItemProperty -Path $regPath -Name "Start" -Value 4 -Type DWord
        Write-Host "  Service $($serviceName) startup disabled in registry." -ForegroundColor Green
    } else {
        Write-Host "  Service $($serviceName) is not installed." -ForegroundColor Gray
    }
}

Write-Host "Remediation completed successfully." -ForegroundColor Cyan
