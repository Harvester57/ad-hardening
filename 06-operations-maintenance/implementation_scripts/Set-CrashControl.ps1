# Set-CrashControl.ps1
# Description: Enables detailed BSOD parameters in the registry.

Write-Host "--- Configuring Detailed BSOD Parameters ---" -ForegroundColor Cyan

$Path = "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl"
if (-not (Test-Path $Path)) {
    New-Item -Path $Path -Force | Out-Null
}

Set-ItemProperty -Path $Path -Name "DisplayParameters" -Value 1 -Type DWord -Force | Out-Null
Write-Host "[+] Detailed BSOD stop parameters configured successfully." -ForegroundColor Green
