# Configure-RemoteEncryptionProtection.ps1
# Description: Configures Microsoft Defender Remote Encryption Protection in Block mode.

Write-Host "Configuring Microsoft Defender Remote Encryption Protection..." -ForegroundColor Cyan

$KeyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Remediation\Behavioral Network Blocks\Brute Force Protection"
if (-not (Test-Path -Path $KeyPath)) {
    New-Item -Path $KeyPath -Force | Out-Null
}
Set-ItemProperty -Path $KeyPath -Name "BruteForceProtectionConfiguredState" -Value 2 -Type DWord -Force

Write-Host "[+] Remote Encryption Protection applied successfully (Block mode)." -ForegroundColor Green
