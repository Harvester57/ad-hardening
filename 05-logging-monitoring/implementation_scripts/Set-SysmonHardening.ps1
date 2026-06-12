# Set-SysmonHardening.ps1
# Configures Sysmon service recovery settings.

Write-Host "--- Hardening Sysmon Service Recovery Settings ---" -ForegroundColor Cyan

# 1. Ensure Sysmon Service is installed and configured
$SysmonService = Get-Service -Name "Sysmon" -ErrorAction SilentlyContinue
if (-not $SysmonService) {
    Write-Warning "Sysmon service is not currently installed. Run the Sysmon installer first."
    exit 1
}

# 2. Configure Service Failure Recovery options via sc.exe
Write-Host "[+] Configuring service failure recovery actions for Sysmon..." -ForegroundColor Gray
$Args = "failure Sysmon actions= restart/60000/restart/60000/restart/60000 reset= 86400"
$Process = Start-Process sc.exe -ArgumentList $Args -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -eq 0) {
    Write-Host "    Sysmon service recovery actions successfully set to auto-restart." -ForegroundColor Green
} else {
    Write-Error "    Failed to set service recovery settings. Exit Code: $($Process.ExitCode)"
}
