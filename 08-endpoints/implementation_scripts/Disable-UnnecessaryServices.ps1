# Disable-UnnecessaryServices.ps1
# Description: Disables unnecessary and high-risk system services on the local machine.

Write-Host "Disabling unnecessary system services..." -ForegroundColor Cyan

$Services = @(
    "Browser",         # Computer Browser
    "irmon",           # Infrared monitor service
    "SharedAccess",    # Internet Connection Sharing (ICS)
    "LxssManager",     # LxssManager (WSL)
    "FTPSVC",          # Microsoft FTP Service
    "sshd",            # OpenSSH SSH Server
    "RpcLocator",      # Remote Procedure Call (RPC) Locator
    "RemoteAccess",    # Routing and Remote Access
    "simptcp",         # Simple TCP/IP Services
    "sacsvr",          # Special Administration Console Helper
    "SSDPSRV",         # SSDP Discovery
    "upnphost",        # UPnP Device Host
    "WMSvc",           # Web Management Service
    "WMPNetworkSvc",   # Windows Media Player Network Sharing Service
    "icssvc",          # Windows Mobile Hotspot Service
    "W3SVC",           # World Wide Web Publishing Service
    "XboxGipSvc",      # Xbox Accessory Management Service
    "XblAuthManager",  # Xbox Live Auth Manager
    "XblGameSave",     # Xbox Live Game Save
    "XboxNetApiSvc"    # Xbox Live Networking Service
)

foreach ($SvcName in $Services) {
    $Service = Get-Service -Name $SvcName -ErrorAction SilentlyContinue
    if ($null -ne $Service) {
        if ($Service.StartType -ne "Disabled") {
            # Stop the service first if running
            if ($Service.Status -eq "Running") {
                Stop-Service -Name $SvcName -Force -ErrorAction SilentlyContinue | Out-Null
            }
            Set-Service -Name $SvcName -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
            Write-Host "[+] Service '$SvcName' stopped and disabled." -ForegroundColor Green
        } else {
            Write-Host "[~] Service '$SvcName' is already disabled." -ForegroundColor Gray
        }
    } else {
        Write-Host "[~] Service '$SvcName' is not installed." -ForegroundColor Gray
    }
}

Write-Host "Unnecessary services configuration completed." -ForegroundColor Green
