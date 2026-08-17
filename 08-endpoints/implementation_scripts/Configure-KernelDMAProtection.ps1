# Configure-KernelDMAProtection.ps1
# Description: Configures registry keys to enable Kernel DMA Protection and block incompatible external DMA devices.

Write-Host "--- Enforcing Kernel DMA Protection ---" -ForegroundColor Cyan

$RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\KernelDMAProtection"
if (-not (Test-Path -Path $RegPath)) {
    New-Item -Path $RegPath -Force | Out-Null
}

# DeviceEnumerationPolicy = 0 (Block all external DMA devices incompatible with Kernel DMA Protection)
Set-ItemProperty -Path $RegPath -Name "DeviceEnumerationPolicy" -Value 0 -Type DWord
Write-Host "Status: Kernel DMA Protection registry configuration applied (DeviceEnumerationPolicy = 0 [Block All])." -ForegroundColor Green
