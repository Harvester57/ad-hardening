# Configure-PawAccountSecureChannel.ps1
# Description: Configures Netlogon secure channel signing, sealing, strong keys, and password rotation on PAWs.

Write-Host "Configuring PAW Domain Member Secure Channel settings..." -ForegroundColor Cyan

$NetlogonPath = "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters"
if (-not (Test-Path -Path $NetlogonPath)) {
    New-Item -Path $NetlogonPath -Force | Out-Null
}

Set-ItemProperty -Path $NetlogonPath -Name "RequireSignOrSeal" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $NetlogonPath -Name "SealSecureChannel" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $NetlogonPath -Name "SignSecureChannel" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $NetlogonPath -Name "DisablePasswordChange" -Value 0 -Type DWord -Force
Set-ItemProperty -Path $NetlogonPath -Name "MaximumPasswordAge" -Value 30 -Type DWord -Force
Set-ItemProperty -Path $NetlogonPath -Name "RequireStrongKey" -Value 1 -Type DWord -Force

Write-Host "Domain Member Secure Channel settings applied successfully." -ForegroundColor Green
