# Get-SMBSigningStatus.ps1
# Description: Audits the registry settings for SMB server and client signing.

Write-Host "--- Auditing SMB Message Signing ---" -ForegroundColor Cyan
$vulnerable = $false

# 1. Audit Server-side SMB Signing
$srvReg = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RequireSecuritySignature" -ErrorAction SilentlyContinue
if ($srvReg -and $srvReg.RequireSecuritySignature -eq 1) {
    Write-Host "[+] SMB Server signing is enforced (RequireSecuritySignature = 1)." -ForegroundColor Green
} else {
    Write-Host "[!] VULNERABLE: SMB Server signing is NOT enforced." -ForegroundColor Red
    $vulnerable = $true
}

# 2. Audit Client-side SMB Signing
$cliReg = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "RequireSecuritySignature" -ErrorAction SilentlyContinue
if ($cliReg -and $cliReg.RequireSecuritySignature -eq 1) {
    Write-Host "[+] SMB Client signing is enforced (RequireSecuritySignature = 1)." -ForegroundColor Green
} else {
    Write-Host "[!] VULNERABLE: SMB Client signing is NOT enforced." -ForegroundColor Red
    $vulnerable = $true
}

if ($vulnerable) {
    Write-Host "Audit result: VULNERABLE" -ForegroundColor Red
} else {
    Write-Host "Audit result: SECURE" -ForegroundColor Green
}
