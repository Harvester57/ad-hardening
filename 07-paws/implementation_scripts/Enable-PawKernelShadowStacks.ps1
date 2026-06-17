# Enable-PawKernelShadowStacks.ps1
# Description: Configures HKLM registry to enable Kernel-mode Hardware-enforced Stack Protection (Kernel Shadow Stacks) for PAWs.

Write-Host "Enabling Kernel-mode Hardware-enforced Stack Protection for PAWs..." -ForegroundColor Cyan

$RegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\KernelShadowStacks"

if (-not (Test-Path $RegPath)) {
    New-Item -Path $RegPath -Force | Out-Null
}

Set-ItemProperty -Path $RegPath -Name "Enabled" -Value 1 -Type DWord
Write-Host "[+] Registry setting for PAW Kernel Shadow Stacks enabled. (Reboot required)." -ForegroundColor Green
