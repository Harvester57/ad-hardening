# Get-PawAccountWdigestCredentialsStatus.ps1
# Description: Audits WDigest plaintext credential caching status on PAWs.

Write-Host "--- Auditing PAW WDigest Credential Caching ---" -ForegroundColor Cyan

$WDigestPath = "HKLM:\System\CurrentControlSet\Control\SecurityProviders\WDigest"

if (-not (Test-Path -Path $WDigestPath)) {
    Write-Host "    [!] MISSING KEY: $WDigestPath" -ForegroundColor Red
    Write-Output "Non-Compliant"
    exit 1
}

$Val = (Get-ItemProperty -Path $WDigestPath -Name "UseLogonCredential" -ErrorAction SilentlyContinue).UseLogonCredential

if ($null -ne $Val -and $Val -eq 0) {
    Write-Host "    [+] UseLogonCredential is set to 0 (Disabled - Secure)." -ForegroundColor Green
    Write-Output "Compliant"
    exit 0
} else {
    Write-Host "    [!] VULNERABLE: UseLogonCredential is '$Val' (Expected: 0)" -ForegroundColor Red
    Write-Output "Non-Compliant"
    exit 1
}
