# Disable-UnusedFeatures.ps1
# Description: Disables unused legacy features, .NET 3.5, and PowerShell 2.0 on the local system.

Write-Host "Disabling unused legacy features and PowerShell 2.0..." -ForegroundColor Cyan

# Check if running as administrator
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "This script must be run as an Administrator."
    exit 1
}

# Feature lists
$DismFeatures = @(
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
    "SimpleTCP"                              # Simple TCP/IP Services
)

$ServerFeatures = @(
    "PowerShell-V2",
    "NET-Framework-Core",
    "FS-SMB1",
    "Internet-Explorer-Optional-amd64",
    "WorkFolders-Client",
    "Xps-Viewer-Dependency",
    "DirectPlay",
    "Telnet-Client",
    "TFTP-Client",
    "Simple-TCPIP"
)

if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) {
    # Windows Server path
    foreach ($FeatName in $ServerFeatures) {
        $Feat = Get-WindowsFeature -Name $FeatName -ErrorAction SilentlyContinue
        if ($null -ne $Feat) {
            if ($Feat.Installed) {
                Write-Host "[*] Removing Server feature: $FeatName..." -ForegroundColor Yellow
                Uninstall-WindowsFeature -Name $FeatName -ErrorAction SilentlyContinue | Out-Null
                Write-Host "[+] Feature '$FeatName' uninstalled." -ForegroundColor Green
            } else {
                Write-Host "[~] Feature '$FeatName' is already uninstalled." -ForegroundColor Gray
            }
        } else {
            # Try DISM fallback
            $DismFeat = Get-WindowsOptionalFeature -Online -FeatureName $FeatName -ErrorAction SilentlyContinue
            if ($null -ne $DismFeat) {
                if ($DismFeat.State -eq "Enabled" -or $DismFeat.State -eq "EnabledPendingRestart") {
                    Write-Host "[*] Disabling optional feature: $FeatName..." -ForegroundColor Yellow
                    Disable-WindowsOptionalFeature -Online -FeatureName $FeatName -NoRestart -ErrorAction SilentlyContinue | Out-Null
                    Write-Host "[+] Feature '$FeatName' disabled." -ForegroundColor Green
                } else {
                    Write-Host "[~] Feature '$FeatName' is already disabled." -ForegroundColor Gray
                }
            } else {
                Write-Host "[~] Feature '$FeatName' is not present in the system." -ForegroundColor Gray
            }
        }
    }
} else {
    # Windows Client path
    foreach ($Feature in $DismFeatures) {
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
}

Write-Host "Optional features configuration completed." -ForegroundColor Green
