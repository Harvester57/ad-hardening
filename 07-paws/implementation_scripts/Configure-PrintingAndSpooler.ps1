# Configure-PrintingAndSpooler.ps1
# Description: Disables the Print Spooler service and configures Point and Print driver installation restrictions on the local PAW.

Write-Host "Hardening Print Spooler and Printer configurations for PAWs..." -ForegroundColor Cyan

# 1. Disable the Print Spooler Service
if (Get-Service -Name "Spooler" -ErrorAction SilentlyContinue) {
    Set-Service -Name "Spooler" -StartupType Disabled -Confirm:$false
    Stop-Service -Name "Spooler" -Force -Confirm:$false
    Write-Host "[+] Print Spooler service has been stopped and disabled." -ForegroundColor Green
} else {
    Write-Host "[+] Print Spooler service not found on local machine." -ForegroundColor Gray
}

# 2. Limit Print Driver Installation to Administrators (Defense-in-Depth)
$PrinterPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
if (-not (Test-Path $PrinterPath)) {
    New-Item -Path $PrinterPath -Force | Out-Null
}
Set-ItemProperty -Path $PrinterPath -Name "RestrictDriverInstallationToAdministrators" -Value 1 -Type DWord -ErrorAction Stop
Write-Host "[+] Print driver installation restricted to Administrators." -ForegroundColor Green
