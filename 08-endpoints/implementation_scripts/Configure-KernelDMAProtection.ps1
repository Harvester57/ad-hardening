# Configure-KernelDMAProtection.ps1
# Description: Configures registry keys to enable Kernel DMA Protection.

Write-Host "--- Enforcing Kernel DMA Protection ---" -ForegroundColor Cyan

$RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\KernelDMAProtection"
if (-not (Test-Path $RegPath)) {
    New-Item -Path $RegPath -Force | Out-Null
}

# DeviceEnumerationPolicy = 1 (Block all external DMA devices until a user logs on)
# Note: For maximum security, set to 0 (Block all). Value 1 is standard for standard endpoints.
Set-ItemProperty -Path $RegPath -Name "DeviceEnumerationPolicy" -Value 1 -Type DWord
Write-Host "Status: Kernel DMA Protection registry configuration applied." -ForegroundColor Green
