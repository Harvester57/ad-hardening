# Configure-PAWLocalSettings.ps1
# Configures local registry keys and services required for PAW isolation.

Write-Host "--- Applying Local PAW Hardening Settings ---" -ForegroundColor Cyan

# 1. Enable LSA Protection (RunAsPPL = 1)
$LsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
if (-not (Test-Path $LsaPath)) {
    New-Item -Path $LsaPath -Force | Out-Null
}
Set-ItemProperty -Path $LsaPath -Name "RunAsPPL" -Value 1 -Type DWord
Write-Host "[+] LSA Protection (RunAsPPL) enabled in registry." -ForegroundColor Green

# 2. Configure AppLocker Service (AppIDSvc) to start automatically
$AppLockerService = Get-Service -Name AppIDSvc -ErrorAction SilentlyContinue
if ($AppLockerService) {
    Set-Service -Name AppIDSvc -StartupType Automatic
    Start-Service -Name AppIDSvc -ErrorAction SilentlyContinue
    Write-Host "[+] Application Identity Service (AppIDSvc) set to Automatic and started." -ForegroundColor Green
} else {
    Write-Warning "[-] Application Identity Service not found on this machine."
}

# 3. Enable Virtualization-Based Security (VBS) and Credential Guard in registry
$DeviceGuardPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"
if (-not (Test-Path $DeviceGuardPath)) {
    New-Item -Path $DeviceGuardPath -Force | Out-Null
}
Set-ItemProperty -Path $DeviceGuardPath -Name "EnableVirtualizationBasedSecurity" -Value 1 -Type DWord
Set-ItemProperty -Path $DeviceGuardPath -Name "RequirePlatformSecurityFeatures" -Value 3 -Type DWord # 3 = Secure Boot and DMA
Set-ItemProperty -Path $DeviceGuardPath -Name "LsaCfgFlags" -Value 1 -Type DWord # 1 = Enabled with UEFI Lock
Write-Host "[+] Device Guard and Credential Guard keys configured." -ForegroundColor Green

Write-Host "`nLocal PAW modifications complete. Please reboot to enforce VBS and LSA protection." -ForegroundColor Cyan
