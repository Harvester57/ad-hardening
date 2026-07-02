# Get-UnusedFeaturesStatus.ps1
# Description: Audits the installation state of unused legacy features on the local system.

Write-Host "--- Auditing Unused Windows Features ---" -ForegroundColor Cyan

# Check if running as administrator
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "This script must be run as an Administrator."
    exit 1
}

$script:Vulnerable = $false

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
            $Color = if ($Feat.Installed -eq $false) { "Green" } else { "Red" }
            Write-Host "    - Feature: $FeatName | Installed: $($Feat.Installed) (Expected: False)" -ForegroundColor $Color
            if ($Feat.Installed) {
                $script:Vulnerable = $true
            }
        } else {
            # Try DISM fallback
            $DismFeat = Get-WindowsOptionalFeature -Online -FeatureName $FeatName -ErrorAction SilentlyContinue
            if ($null -ne $DismFeat) {
                $IsEnabled = ($DismFeat.State -eq "Enabled" -or $DismFeat.State -eq "EnabledPendingRestart")
                $Color = if (-not $IsEnabled) { "Green" } else { "Red" }
                Write-Host "    - Feature: $FeatName (DISM) | State: $($DismFeat.State) (Expected: Disabled)" -ForegroundColor $Color
                if ($IsEnabled) {
                    $script:Vulnerable = $true
                }
            } else {
                Write-Host "    - Feature: $FeatName | Not Present (Compliant)" -ForegroundColor Green
            }
        }
    }
} else {
    # Windows Client path
    foreach ($Feature in $DismFeatures) {
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
}

if ($script:Vulnerable) {
    Write-Host "Audit Result: VULNERABLE" -ForegroundColor Red
    exit 1
} else {
    Write-Host "Audit Result: SECURE" -ForegroundColor Green
    exit 0
}
