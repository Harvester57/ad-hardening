# Configure-UntrustedFontBlocking.ps1
# Description: Configures Untrusted Font Blocking mitigation to block untrusted fonts and log events on Domain Controllers.

$RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\MitigationOptions"
$ValueName = "MitigationOptions_FontBocking"
$ValueData = "1000000000000"

Write-Host "Applying hardening requirement: Configure Untrusted Font Blocking..." -ForegroundColor Cyan

if (-not (Test-Path $RegPath)) {
    New-Item -Path $RegPath -Force | Out-Null
}

Set-ItemProperty -Path $RegPath -Name $ValueName -Value $ValueData -Type String -Force | Out-Null
Write-Host "Hardening applied successfully." -ForegroundColor Green
