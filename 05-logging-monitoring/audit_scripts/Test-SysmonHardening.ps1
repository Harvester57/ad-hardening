# Test-SysmonHardening.ps1
# Audits Sysmon service, driver execution, and recovery actions.

Write-Host "--- Auditing Sysmon Hardening State ---" -ForegroundColor Cyan

# 1. Verify Sysmon Service status
$SysmonService = Get-Service -Name "Sysmon" -ErrorAction SilentlyContinue
$ServiceStatus = "Stopped"
if ($SysmonService) {
    $ServiceStatus = $SysmonService.Status
}
$ServiceColor = if ($ServiceStatus -eq "Running") { "Green" } else { "Red" }
Write-Host "    - Sysmon Service Status: $($ServiceStatus) (Required = Running)" -ForegroundColor $ServiceColor

# 2. Verify Sysmon Filter Driver (SysmonDrv)
$DriverRunning = $false
$DriverCheck = fltmc.exe filters
foreach ($Line in $DriverCheck) {
    if ($Line -match "SysmonDrv") {
        $DriverRunning = $true
    }
}
$DriverColor = if ($DriverRunning) { "Green" } else { "Red" }
Write-Host "    - Sysmon Kernel Driver Loaded: $($DriverRunning) (Required = True)" -ForegroundColor $DriverColor

# 3. Verify Service Failure Recovery Options
$FailureInfo = sc.exe qfailure Sysmon
$HasReset = $false
$HasRestart = $false
foreach ($Line in $FailureInfo) {
    if ($Line -match "RESET_PERIOD\s+:\s+86400") {
        $HasReset = $true
    }
    if ($Line -match "FAILURE_ACTIONS\s+:\s+RESTART") {
        $HasRestart = $true
    }
}

$RecoveryColor = if ($HasReset -and $HasRestart) { "Green" } else { "Red" }
Write-Host "    - Recovery Configuration: ResetConfigured=$($HasReset), RestartActionsConfigured=$($HasRestart)" -ForegroundColor $RecoveryColor
