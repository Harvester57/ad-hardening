# Configure-KernelDMAProtection.ps1
# Description: Configures registry keys to enable Kernel DMA Protection.

Write-Host "--- Enforcing Kernel DMA Protection ---" -ForegroundColor Cyan

$RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\KernelDMAProtection"
if (-not (Test-Path $RegPath)) {
    New-Item -Path $RegPath -Force | Out-Null
}

# DeviceEnumerationPolicy = 0 (Block all DMA until user logs on)
Set-ItemProperty -Path $RegPath -Name "DeviceEnumerationPolicy" -Value 0 -Type DWord
Write-Host "Status: Kernel DMA Protection registry configuration applied." -ForegroundColor Green
