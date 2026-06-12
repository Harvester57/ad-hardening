# Get-SafeModeNonAdminsStatus.ps1
# Description: Checks the current configuration state of SafeModeBlockNonAdmins registry setting.

$RegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$ValueName = "SafeModeBlockNonAdmins"

Write-Host "Auditing hardening requirement: Restrict Safe Mode access to administrators..." -ForegroundColor Cyan

if (Test-Path $RegPath) {
    $value = Get-ItemProperty -Path $RegPath -Name $ValueName -ErrorAction SilentlyContinue
    if ($null -ne $value -and $value.$ValueName -eq 1) {
        Write-Host "Audit Result: Compliant. Standard users are blocked from logging in during Safe Mode ($ValueName = 1)." -ForegroundColor Green
        exit 0
    }
}

Write-Host "Audit Result: Non-Compliant. Standard users are allowed to log in during Safe Mode." -ForegroundColor Red
exit 1
