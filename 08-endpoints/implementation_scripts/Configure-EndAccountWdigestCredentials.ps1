# Configure-EndAccountWdigestCredentials.ps1
Write-Host "Disabling WDigest plaintext credential caching on Endpoints..." -ForegroundColor Cyan

$WDigestPath = "HKLM:\System\CurrentControlSet\Control\SecurityProviders\WDigest"
if (-not (Test-Path $WDigestPath)) { New-Item -Path $WDigestPath -Force | Out-Null }
Set-ItemProperty -Path $WDigestPath -Name "UseLogonCredential" -Value 0 -Type DWord -Force

Write-Host "WDigest credential caching disabled." -ForegroundColor Green
