# Deploy-ADHardeningAudit.ps1
# Description: Orchestrates local deployment, LCM configuration, compilation, and execution of the DSC audit configuration.
# Target Engine: Windows PowerShell 5.1

param (
    [Parameter(Mandatory = $true)]
    [ValidateSet("DomainController", "PAW", "Endpoint")]
    [string]$Profile,

    [Parameter(Mandatory = $false)]
    [string]$SourcePath = "$PSScriptRoot\..",

    [Parameter(Mandatory = $false)]
    [string]$TargetPath = "C:\ProgramData\ADHardening",

    [Parameter(Mandatory = $false)]
    [switch]$CompileOnly
)

# 1. Administrator Privilege Check
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin -and -not $CompileOnly) {
    Write-Error "This script must be run as an Administrator to configure LCM and apply DSC configuration."
    return
}

Write-Host "--- Starting AD Hardening DSC Audit Deployment ---" -ForegroundColor Cyan
Write-Host "Profile: $Profile" -ForegroundColor Yellow
Write-Host "Source Path: $SourcePath" -ForegroundColor Yellow
Write-Host "Target Path: $TargetPath" -ForegroundColor Yellow

# 2. Synchronize Audit Scripts to Target Path
Write-Host "Synchronizing audit scripts to target path..." -ForegroundColor Cyan
$modules = @(
    "01-architecture",
    "02-domain-controllers",
    "03-identities-services",
    "04-network-firewall",
    "05-logging-monitoring",
    "06-operations-maintenance",
    "07-paws",
    "08-endpoints"
)

foreach ($module in $modules) {
    $srcDir = Join-Path $SourcePath "$module\audit_scripts"
    $destDir = Join-Path $TargetPath "$module\audit_scripts"
    if (Test-Path -Path $srcDir) {
        if (-not (Test-Path -Path $destDir)) {
            $null = New-Item -Path $destDir -ItemType Directory -Force
        }
        Write-Host "  Copying audit scripts for module: $module" -ForegroundColor DarkGray
        Copy-Item -Path "$srcDir\*" -Destination $destDir -Force
    }
}

# 3. Configure LCM (ApplyAndMonitor)
$lcmBuildPath = Join-Path $PSScriptRoot "Build\LCM"
if (-not $CompileOnly) {
    Write-Host "Configuring Local Configuration Manager (LCM) to 'ApplyAndMonitor' mode..." -ForegroundColor Cyan
    
    if (-not (Test-Path -Path $lcmBuildPath)) {
        $null = New-Item -Path $lcmBuildPath -ItemType Directory -Force
    }

    # Inline Meta-Configuration for LCM
    $lcmConfigScript = @"
[DSCLocalConfigurationManager()]
Configuration ConfigureLCM {
    Node localhost {
        Settings {
            ConfigurationMode = 'ApplyAndMonitor'
            RefreshMode = 'Push'
            RebootNodeIfNeeded = `$false
        }
    }
}
"@
    $lcmScriptFile = Join-Path $lcmBuildPath "ConfigureLCM.ps1"
    Set-Content -Path $lcmScriptFile -Value $lcmConfigScript -Force
    
    # Compile and apply LCM Configuration
    . $lcmScriptFile
    ConfigureLCM -OutputPath $lcmBuildPath | Out-Null
    Set-DscLocalConfigurationManager -Path $lcmBuildPath -Force -Verbose
}

# 4. Compile DSC Configuration
Write-Host "Compiling DSC Configuration..." -ForegroundColor Cyan
$configBuildPath = Join-Path $PSScriptRoot "Build\Config"
if (-not (Test-Path -Path $configBuildPath)) {
    $null = New-Item -Path $configBuildPath -ItemType Directory -Force
}

$dscConfigFile = Join-Path $PSScriptRoot "ADHardeningAudit.ps1"
if (-not (Test-Path -Path $dscConfigFile)) {
    Write-Error "DSC Configuration script not found at: $dscConfigFile"
    return
}

# Dot-source the configuration and compile it
. $dscConfigFile
ADHardeningAudit -Profile $Profile -AuditScriptsSourcePath $TargetPath -OutputPath $configBuildPath | Out-Null

# 5. Apply DSC Configuration (Run Audits)
if (-not $CompileOnly) {
    Write-Host "Applying DSC Configuration and executing audits (this may take a few minutes)..." -ForegroundColor Cyan
    Start-DscConfiguration -Path $configBuildPath -Wait -Force -Verbose

    Write-Host "Auditing completed. Reading compliance status..." -ForegroundColor Cyan
    $status = Get-DscConfigurationStatus
    if ($status) {
        $statusColor = "Red"
        if ($status.Status -eq "Success") {
            $statusColor = "Green"
        }
        $compliantColor = "Red"
        if ($status.InDesiredState -eq $true) {
            $compliantColor = "Green"
        }
        Write-Host "Compliance Status: $($status.Status)" -ForegroundColor $statusColor
        Write-Host "Compliance Start Time: $($status.StartDate)" -ForegroundColor Gray
        Write-Host "Host compliant with all controls: $($status.InDesiredState)" -ForegroundColor $compliantColor
    } else {
        Write-Warning "Could not retrieve DSC Configuration Status."
    }
} else {
    Write-Host "Compilation successful. MOF file is located at: $configBuildPath" -ForegroundColor Green
}

Write-Host "--- Deployment script finished ---" -ForegroundColor Cyan
