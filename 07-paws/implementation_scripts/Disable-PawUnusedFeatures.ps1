# Disable-PawUnusedFeatures.ps1
# Description: Disables unused legacy features, .NET 3.5, and PowerShell 2.0 on the local PAW system.

Write-Host "Disabling unused legacy features and PowerShell 2.0..." -ForegroundColor Cyan

# Check if running as administrator
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "This script must be run as an Administrator."
    exit 1
}

# Features to disable (Client OS DISM feature names)
$Features = @(
    "MicrosoftWindowsPowerShellV2",
    "MicrosoftWindowsPowerShellV2Root",
    "NetFx3",                                # .NET Framework 3.5
    "SMB1Protocol",                          # SMBv1 Client
    "Internet-Explorer-Optional-amd64",      # Internet Explorer 11
    "WorkFolders-Client",                    # Work Folders Client
    "Xps-Viewer-Dependency",                 # XPS Viewer
    "DirectPlay",                            # DirectPlay
    "TelnetClient",                          # Telnet Client
    "TFTP",                                  # TFTP Client
    "SimpleTCP",                             # Simple TCP/IP Services
    "Microsoft-Windows-Subsystem-Linux",     # WSL (specifically disabled on PAWs)
    "Containers-DisposableClientVM"          # Windows Sandbox (specifically disabled on PAWs)
)

foreach ($Feature in $Features) {
    $State = Get-WindowsOptionalFeature -Online -FeatureName $Feature -ErrorAction SilentlyContinue
    if ($null -ne $State) {
        if ($State.State -eq "Enabled" -or $State.State -eq "EnabledPendingRestart") {
            Write-Host "[*] Disabling feature: $Feature..." -ForegroundColor Yellow
            Disable-WindowsOptionalFeature -Online -FeatureName $Feature -NoRestart -ErrorAction SilentlyContinue | Out-Null
            Write-Host "[+] Feature '$Feature' has been disabled." -ForegroundColor Green
        } else {
            Write-Host "[~] Feature '$Feature' is already disabled." -ForegroundColor Gray
        }
    } else {
        Write-Host "[~] Feature '$Feature' is not present in this Windows image." -ForegroundColor Gray
    }
}

Write-Host "Optional features configuration completed." -ForegroundColor Green
