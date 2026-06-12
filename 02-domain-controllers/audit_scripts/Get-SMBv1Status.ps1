# Get-SMBv1Status.ps1
# Description: Audits the registry configuration of SMBv1 server and client components.

Write-Host "--- Auditing SMBv1 Configuration ---" -ForegroundColor Cyan
$vulnerable = $false

# Check Server configuration
if (Get-Command -Name Get-SmbServerConfiguration -ErrorAction SilentlyContinue) {
    $smbConfig = Get-SmbServerConfiguration
    if ($smbConfig.EnableSMB1Protocol -eq $true) {
        Write-Host "[!] VULNERABLE: SMBv1 Server protocol is enabled via configuration." -ForegroundColor Red
        $vulnerable = $true
    } else {
        Write-Host "[+] SMBv1 Server protocol is disabled." -ForegroundColor Green
    }
} else {
    $srvReg = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -ErrorAction SilentlyContinue
    if ($srvReg -and $srvReg.SMB1 -eq 1) {
        Write-Host "[!] VULNERABLE: SMB1 registry parameter is set to 1 (Enabled)." -ForegroundColor Red
        $vulnerable = $true
    } else {
        Write-Host "[+] SMB1 registry parameter is disabled or not present." -ForegroundColor Green
    }
}

# Check Client configuration
$driverReg = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10" -Name "Start" -ErrorAction SilentlyContinue
if ($driverReg -and $driverReg.Start -ne 4) {
    Write-Host "[!] VULNERABLE: mrxsmb10 client driver is not disabled (Start value: $($driverReg.Start))." -ForegroundColor Red
    $vulnerable = $true
} else {
    Write-Host "[+] mrxsmb10 client driver is disabled." -ForegroundColor Green
}

if ($vulnerable) {
    Write-Host "Audit result: VULNERABLE" -ForegroundColor Red
} else {
    Write-Host "Audit result: SECURE" -ForegroundColor Green
}
