# Audit-CrashControl.ps1
# Description: Audits whether detailed BSOD parameters are enabled in the registry.

Write-Host "--- Auditing Detailed BSOD Parameters ---" -ForegroundColor Cyan

$Path = "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl"
if (Test-Path $Path) {
    $Val = Get-ItemProperty -Path $Path -Name "DisplayParameters" -ErrorAction SilentlyContinue
    if ($Val -and $Val.DisplayParameters -eq 1) {
        Write-Host "[+] Detailed BSOD stop parameters are ENABLED (Compliant)." -ForegroundColor Green
    } else {
        Write-Host "[-] Detailed BSOD stop parameters are DISABLED (Non-Compliant)." -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "[-] Registry path HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl not found." -ForegroundColor Red
    exit 1
}
