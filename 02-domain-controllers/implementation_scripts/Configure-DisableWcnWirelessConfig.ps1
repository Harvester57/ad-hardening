# Configure-DisableWcnWirelessConfig.ps1
# Description: Disables Windows Connect Now wireless settings configuration registrars on Domain Controllers.

Write-Host "Disabling Windows Connect Now Wireless Settings Configuration..." -ForegroundColor Cyan

$WcnRegsPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars"
if (-not (Test-Path -Path $WcnRegsPath)) {
    New-Item -Path $WcnRegsPath -Force | Out-Null
}

Set-ItemProperty -Path $WcnRegsPath -Name "EnableRegistrars" -Value 0 -Type DWord -ErrorAction Stop
Set-ItemProperty -Path $WcnRegsPath -Name "DisableUPnPRegistrar" -Value 1 -Type DWord -ErrorAction Stop
Set-ItemProperty -Path $WcnRegsPath -Name "DisableInBand802DOT11Registrar" -Value 1 -Type DWord -ErrorAction Stop
Set-ItemProperty -Path $WcnRegsPath -Name "DisableFlashConfigRegistrar" -Value 1 -Type DWord -ErrorAction Stop
Set-ItemProperty -Path $WcnRegsPath -Name "DisableWPDRegistrar" -Value 1 -Type DWord -ErrorAction Stop

Write-Host "Windows Connect Now Wireless Settings Configuration disabled successfully." -ForegroundColor Green
