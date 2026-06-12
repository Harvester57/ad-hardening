# Get-KerberosEncryptionStatus.ps1
# Description: Audits the allowed Kerberos encryption types in the registry.

Write-Host "--- Auditing Kerberos Encryption Types ---" -ForegroundColor Cyan

$regPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"
$regVal = Get-ItemProperty -Path $regPath -Name "SupportedEncryptionTypes" -ErrorAction SilentlyContinue

if ($regVal) {
    $encTypes = $regVal.SupportedEncryptionTypes
    
    # Check if weak algorithms are enabled (DES = 0x1, 0x2; RC4 = 0x4)
    $hasDES = ($encTypes -band 0x1) -or ($encTypes -band 0x2)
    $hasRC4 = ($encTypes -band 0x4)
    $hasAES128 = ($encTypes -band 0x8)
    $hasAES256 = ($encTypes -band 0x10)
    
    if ($hasDES -or $hasRC4) {
        Write-Host "[!] VULNERABLE: Weak Kerberos encryption algorithms are allowed (DES: $($hasDES), RC4: $($hasRC4)). SupportedEncryptionTypes raw value: $($encTypes)." -ForegroundColor Red
    } else {
        if ($hasAES128 -and $hasAES256) {
            Write-Host "[+] Kerberos encryption is secure. Restricting to AES128/AES256 (SupportedEncryptionTypes: $($encTypes))." -ForegroundColor Green
        } else {
            Write-Host "[-] Kerberos encryption configuration is custom. AES128: $($hasAES128), AES256: $($hasAES256) (SupportedEncryptionTypes: $($encTypes))." -ForegroundColor Yellow
        }
    }
} else {
    Write-Host "[!] VULNERABLE: SupportedEncryptionTypes registry value is missing. Default behavior allows insecure RC4." -ForegroundColor Red
}
