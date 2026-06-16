# Get-UntrustedFontBlockingStatus.ps1
# Description: Checks the current configuration state of Untrusted Font Blocking registry setting on Domain Controllers.

$RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\MitigationOptions"
$ValueName = "MitigationOptions_FontBocking"
$ExpectedValue = "1000000000000"

Write-Host "Auditing hardening requirement: Configure Untrusted Font Blocking..." -ForegroundColor Cyan

if (Test-Path $RegPath) {
    $value = Get-ItemProperty -Path $RegPath -Name $ValueName -ErrorAction SilentlyContinue
    if ($null -ne $value -and $value.$ValueName -eq $ExpectedValue) {
        Write-Host "Audit Result: Compliant. Untrusted fonts are blocked and logged ($($ValueName) = $($ExpectedValue))." -ForegroundColor Green
        exit 0
    }
}

Write-Host "Audit Result: Non-Compliant. Untrusted fonts are not configured to block and log." -ForegroundColor Red
exit 1
