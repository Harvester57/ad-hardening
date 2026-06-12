# Set-PawDMAPhysicalSecurity.ps1
# Description: Hardens local registry keys on PAWs to mitigate DMA attacks, disable standby sleep states, and restrict unencrypted USB writing.

Write-Host "Applying PAW DMA and physical security hardening..." -ForegroundColor Cyan

# 1. Disable Standby Sleep States (S1-S3)
$SleepPath = "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab"
if (-not (Test-Path $SleepPath)) {
    New-Item -Path $SleepPath -Force | Out-Null
}
Set-ItemProperty -Path $SleepPath -Name "ACSettingIndex" -Value 0 -Type DWord
Set-ItemProperty -Path $SleepPath -Name "DCSettingIndex" -Value 0 -Type DWord
Write-Host "[+] Standby sleep states (S1-S3) disabled." -ForegroundColor Green

# 2. Configure Wake Password Requirement
$WakePath = "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51"
if (-not (Test-Path $WakePath)) {
    New-Item -Path $WakePath -Force | Out-Null
}
Set-ItemProperty -Path $WakePath -Name "ACSettingIndex" -Value 1 -Type DWord
Set-ItemProperty -Path $WakePath -Name "DCSettingIndex" -Value 1 -Type DWord
Write-Host "[+] Wake password requirement enforced." -ForegroundColor Green

# 3. BitLocker DMA and Removable Storage Settings
$FvePath = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
if (-not (Test-Path $FvePath)) {
    New-Item -Path $FvePath -Force | Out-Null
}
Set-ItemProperty -Path $FvePath -Name "DisableExternalDMAUnderLock" -Value 1 -Type DWord
Set-ItemProperty -Path $FvePath -Name "RDVDenyCrossOrg" -Value 0 -Type DWord

$FvePolicyPath = "HKLM:\System\CurrentControlSet\Policies\Microsoft\FVE"
if (-not (Test-Path $FvePolicyPath)) {
    New-Item -Path $FvePolicyPath -Force | Out-Null
}
Set-ItemProperty -Path $FvePolicyPath -Name "RDVDenyWriteAccess" -Value 1 -Type DWord
Write-Host "[+] BitLocker DMA under lock and unencrypted USB write blocks configured." -ForegroundColor Green

# 4. Device Installation Restrictions (Block SBP-2 class)
$RestrictPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions"
if (-not (Test-Path $RestrictPath)) {
    New-Item -Path $RestrictPath -Force | Out-Null
}
Set-ItemProperty -Path $RestrictPath -Name "DenyDeviceClasses" -Value 1 -Type DWord
Set-ItemProperty -Path $RestrictPath -Name "DenyDeviceClassesRetroactive" -Value 1 -Type DWord

$DenyClassPath = Join-Path $RestrictPath "DenyDeviceClasses"
if (-not (Test-Path $DenyClassPath)) {
    New-Item -Path $DenyClassPath -Force | Out-Null
}
Set-ItemProperty -Path $DenyClassPath -Name "1" -Value "{d48179be-ec20-11d1-b6b8-00c04fa372a7}" -Type String
Write-Host "[+] Device installation blocks for SBP-2 class enabled." -ForegroundColor Green

# 5. Kernel DMA Protection (Block all external DMA permanently for PAWs)
$KDmaPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\KernelDMAProtection"
if (-not (Test-Path $KDmaPath)) {
    New-Item -Path $KDmaPath -Force | Out-Null
}
Set-ItemProperty -Path $KDmaPath -Name "DeviceEnumerationPolicy" -Value 0 -Type DWord
Write-Host "[+] Kernel DMA Protection DeviceEnumerationPolicy set to 0 (Block all)." -ForegroundColor Green

Write-Host "PAW DMA and physical security settings applied successfully." -ForegroundColor Green
