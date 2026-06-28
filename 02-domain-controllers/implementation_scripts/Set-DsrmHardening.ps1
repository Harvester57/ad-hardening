# Set-DsrmHardening.ps1
# Description: Configures DsrmAdminLogonBehavior to restrict network logons.

$RegPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
$ValueName = "DsrmAdminLogonBehavior"
$ValueData = 1 # Restrict network logons

Write-Host "Applying hardening: Restricting DSRM Admin Logon Behavior..." -ForegroundColor Cyan

if (-not (Test-Path $RegPath)) {
    New-Item -Path $RegPath -Force | Out-Null
}

Set-ItemProperty -Path $RegPath -Name $ValueName -Value $ValueData -Type DWord
Write-Host "[+] Registry parameter set successfully: $ValueName = $ValueData" -ForegroundColor Green

# Instructions for DSRM password sync
Write-Host "`n[NOTE] Ensure that you synchronize the DSRM Administrator password with the Domain Administrator account." -ForegroundColor Yellow
Write-Host "Run the following command to sync passwords:" -ForegroundColor Yellow
Write-Host "  ntdsutil `"set dsrm password`" `"sync from domain account administrator`" q q" -ForegroundColor Yellow
