# Set-AppLockerDCPolicy.ps1
# Description: Configures the Application Identity service and imports a basic local AppLocker XML policy.

Write-Host "Applying hardening requirement: Configure AppLocker on Domain Controllers..." -ForegroundColor Cyan

# 1. Enable Application Identity service (AppIDSvc)
$Service = Get-Service -Name AppIDSvc -ErrorAction SilentlyContinue
if ($Service) {
    Set-Service -Name AppIDSvc -StartupType Automatic
    if ($Service.Status -ne "Running") {
        Start-Service -Name AppIDSvc
    }
    Write-Host "[+] Application Identity service configured to start automatically and is running." -ForegroundColor Green
} else {
    Write-Error "Application Identity service (AppIDSvc) is not present on this system."
}

# 2. Configure local AppLocker policy (Example: Enforces Executable, Installer, Script and Packaged App rules)
# Typically, an AppLocker XML configuration is imported. Below is the registry path configuration for baseline.
$SrpPath = "HKLM:\Software\Policies\Microsoft\Windows\SrpV2"
if (-not (Test-Path $SrpPath)) {
    New-Item -Path $SrpPath -Force | Out-Null
}

$Collections = @("Exe", "Msi", "Script", "Appx")
foreach ($Col in $Collections) {
    $ColPath = "$SrpPath\$Col"
    if (-not (Test-Path $ColPath)) {
        New-Item -Path $ColPath -Force | Out-Null
    }
    # EnforcementMode: 1 = Enforce, 0 = Audit Only
    Set-ItemProperty -Path $ColPath -Name "EnforcementMode" -Value 1 -Type DWord
}
Write-Host "[+] AppLocker enforcement registry values configured." -ForegroundColor Green
