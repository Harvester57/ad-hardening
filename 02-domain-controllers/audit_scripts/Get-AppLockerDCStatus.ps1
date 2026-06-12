# Get-AppLockerDCStatus.ps1
# Description: Checks the configuration state of the AppIDSvc service and AppLocker registry paths.

Write-Host "--- Auditing AppLocker Configuration ---" -ForegroundColor Cyan

# 1. Audit service state
$AppIDSvc = Get-Service -Name AppIDSvc -ErrorAction SilentlyContinue
if ($AppIDSvc) {
    $SvcColor = if ($AppIDSvc.Status -eq "Running" -and $AppIDSvc.StartType -eq "Automatic") { "Green" } else { "Yellow" }
    Write-Host "    - Application Identity Service: $($AppIDSvc.Status) | Startup: $($AppIDSvc.StartType) (Expected: Running | Automatic)" -ForegroundColor $SvcColor
} else {
    Write-Host "    - Application Identity Service: NOT INSTALLED" -ForegroundColor Red
}

# 2. Audit enforcement registry settings
$SrpPath = "HKLM:\Software\Policies\Microsoft\Windows\SrpV2"
$Collections = @("Exe", "Msi", "Script", "Appx")

if (Test-Path $SrpPath) {
    foreach ($Col in $Collections) {
        $ColPath = "$SrpPath\$Col"
        if (Test-Path $ColPath) {
            $Val = Get-ItemProperty -Path $ColPath -Name "EnforcementMode" -ErrorAction SilentlyContinue
            if ($null -ne $Val) {
                $Mode = if ($Val.EnforcementMode -eq 1) { "Enforced" } else { "Audit Only" }
                $Color = if ($Val.EnforcementMode -eq 1) { "Green" } else { "Yellow" }
                Write-Host "    - Collection $Col Enforcement: $Mode (Value: $($Val.EnforcementMode))" -ForegroundColor $Color
            } else {
                Write-Host "    - Collection $Col Enforcement: NOT CONFIGURED" -ForegroundColor Red
            }
        } else {
            Write-Host "    - Collection $Col Path: NOT FOUND" -ForegroundColor Red
        }
    }
} else {
    Write-Host "[-] AppLocker registry base path (SrpV2) not found. Policy is not deployed." -ForegroundColor Red
}

# 3. Audit NTVDM Disable Status
$NtvdmPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat"
if (Test-Path $NtvdmPath) {
    $AppCompatVal = Get-ItemProperty -Path $NtvdmPath -Name "Prevent16BitApp" -ErrorAction SilentlyContinue
    if ($null -ne $AppCompatVal -and $AppCompatVal.Prevent16BitApp -eq 1) {
        Write-Host "    - NTVDM (16-bit AppCompat): Disabled (Secure)" -ForegroundColor Green
    } else {
        Write-Host "    - NTVDM (16-bit AppCompat): Enabled or Not Configured (Expected: Disabled)" -ForegroundColor Yellow
    }
} else {
    Write-Host "    - NTVDM (16-bit AppCompat): Not Configured (Expected: Disabled)" -ForegroundColor Yellow
}
