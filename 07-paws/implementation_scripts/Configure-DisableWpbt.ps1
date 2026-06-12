# Configure-DisableWpbt.ps1
# Description: Disables Windows Platform Binary Table (WPBT) execution in the registry.

Write-Host "Applying hardening requirement: Disable WPBT Execution..." -ForegroundColor Cyan

$RegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"
$ValueName = "DisableWpbtExecution"
$ValueData = 1

if (-not (Test-Path $RegPath)) {
    New-Item -Path $RegPath -Force | Out-Null
}

Set-ItemProperty -Path $RegPath -Name $ValueName -Value $ValueData -Type DWord
Write-Host "Registry setting DisableWpbtExecution configured to 1." -ForegroundColor Green
