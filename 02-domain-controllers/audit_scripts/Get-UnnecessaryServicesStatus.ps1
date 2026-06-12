# Get-UnnecessaryServicesStatus.ps1
# Description: Audits the registry startup state of unnecessary system services.

Write-Host "--- Auditing Unnecessary Services on Domain Controllers ---" -ForegroundColor Cyan

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

$vulnerableCount = 0

foreach ($serviceName in $services) {
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName"
    if (Test-Path $regPath) {
        $startVal = Get-ItemProperty -Path $regPath -Name "Start" -ErrorAction SilentlyContinue
        if ($startVal) {
            $start = $startVal.Start
            if ($start -eq 4) {
                Write-Host "[+] Service $($serviceName) is secure (Disabled)." -ForegroundColor Green
            } else {
                Write-Host "[!] VULNERABLE: Service $($serviceName) startup type is not Disabled (Start value is $($start))." -ForegroundColor Red
                $vulnerableCount = $vulnerableCount + 1
            }
        } else {
            Write-Host "[!] VULNERABLE: Service $($serviceName) exists but Start registry value is missing." -ForegroundColor Red
            $vulnerableCount = $vulnerableCount + 1
        }
    } else {
        Write-Host "[+] Service $($serviceName) is not installed (Secure)." -ForegroundColor Green
    }
}

if ($vulnerableCount -gt 0) {
    Write-Host "Audit failed: $($vulnerableCount) service(s) are not disabled." -ForegroundColor Red
} else {
    Write-Host "Audit passed: All non-essential services are disabled or not installed." -ForegroundColor Green
}
