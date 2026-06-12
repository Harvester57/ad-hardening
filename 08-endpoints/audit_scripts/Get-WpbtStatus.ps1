# Get-WpbtStatus.ps1
# Description: Audits the registry state for WPBT execution prevention.

Write-Host "--- Auditing WPBT Security Posture ---" -ForegroundColor Cyan

$RegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"
$ValueName = "DisableWpbtExecution"

$RegistryValue = Get-ItemProperty -Path $RegPath -Name $ValueName -ErrorAction SilentlyContinue

if ($RegistryValue) {
    $Setting = $RegistryValue.DisableWpbtExecution
    if ($Setting -eq 1) {
        Write-Host "Status: WPBT execution is disabled (DisableWpbtExecution = 1)." -ForegroundColor Green
    } else {
        Write-Host "VULNERABLE: WPBT execution is enabled. Value is $($Setting)." -ForegroundColor Red
    }
} else {
    Write-Host "VULNERABLE: DisableWpbtExecution registry value is not configured (defaulting to execution enabled)." -ForegroundColor Red
}
