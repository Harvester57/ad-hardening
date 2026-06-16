# Get-PawUnnecessaryServicesStatus.ps1
# Description: Audits the startup configuration of unnecessary system services on the local PAW system.

Write-Host "--- Auditing Unnecessary System Services ---" -ForegroundColor Cyan

$script:Vulnerable = $false

$Services = @(
    "Browser",
    "irmon",
    "SharedAccess",
    "LxssManager",
    "FTPSVC",
    "sshd",
    "RpcLocator",
    "RemoteAccess",
    "simptcp",
    "sacsvr",
    "SSDPSRV",
    "upnphost",
    "WMSvc",
    "WMPNetworkSvc",
    "icssvc",
    "W3SVC",
    "XboxGipSvc",
    "XblAuthManager",
    "XblGameSave",
    "XboxNetApiSvc"
)

foreach ($SvcName in $Services) {
    $Service = Get-Service -Name $SvcName -ErrorAction SilentlyContinue
    if ($null -ne $Service) {
        $Color = if ($Service.StartType -eq "Disabled") { "Green" } else { "Red" }
        Write-Host "    - Service: $SvcName | StartType: $($Service.StartType) (Expected: Disabled)" -ForegroundColor $Color
        
        if ($Service.StartType -ne "Disabled") {
            $script:Vulnerable = $true
        }
    } else {
        Write-Host "    - Service: $SvcName | Not Installed (Compliant)" -ForegroundColor Green
    }
}

if ($script:Vulnerable) {
    Write-Host "Audit Result: VULNERABLE" -ForegroundColor Red
    exit 1
} else {
    Write-Host "Audit Result: SECURE" -ForegroundColor Green
    exit 0
}
