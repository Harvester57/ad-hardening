# Configure-KerberosEncryptionTypes.ps1
# Description: Restricts Kerberos encryption types to AES128, AES256, and Future types.

Write-Host "Applying hardening requirement: Restrict Kerberos Encryption Types..." -ForegroundColor Cyan

$regPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

# 2147483640 (0x7FFFFFF8) enables AES128, AES256, and Future encryption types
Set-ItemProperty -Path $regPath -Name "SupportedEncryptionTypes" -Value 2147483640 -Type DWord
Write-Host "Kerberos encryption types restricted to AES and future types." -ForegroundColor Green
