# Get-PawUnusedFeaturesStatus.ps1
# Description: Audits the installation state of unused legacy features on the local PAW system.

Write-Host "--- Auditing Unused Windows Features ---" -ForegroundColor Cyan

# Check if running as administrator
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "This script must be run as an Administrator."
    exit 1
}

$script:Vulnerable = $false

# Features to check (Client OS DISM feature names)
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
        $IsEnabled = ($State.State -eq "Enabled" -or $State.State -eq "EnabledPendingRestart")
        $Color = if (-not $IsEnabled) { "Green" } else { "Red" }
        Write-Host "    - Feature: $Feature | State: $($State.State) (Expected: Disabled)" -ForegroundColor $Color
        
        if ($IsEnabled) {
            $script:Vulnerable = $true
        }
    } else {
        Write-Host "    - Feature: $Feature | Not Present (Compliant)" -ForegroundColor Green
    }
}

if ($script:Vulnerable) {
    Write-Host "Audit Result: VULNERABLE" -ForegroundColor Red
    exit 1
} else {
    Write-Host "Audit Result: SECURE" -ForegroundColor Green
    exit 0
}
