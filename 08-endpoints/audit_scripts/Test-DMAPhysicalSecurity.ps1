# Test-DMAPhysicalSecurity.ps1
# Description: Audits local registry configuration for standby settings, DMA protection under lock, USB restrictions, and blocked device setup classes.

Write-Host "--- Auditing DMA and Physical Security ---" -ForegroundColor Cyan

# 1. Audit Standby Settings
$SleepPath = "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab"
$AcSleep = Get-ItemProperty -Path $SleepPath -Name "ACSettingIndex" -ErrorAction SilentlyContinue
$DcSleep = Get-ItemProperty -Path $SleepPath -Name "DCSettingIndex" -ErrorAction SilentlyContinue

$AcSleepVal = if ($AcSleep) { $AcSleep.ACSettingIndex } else { 1 }
$DcSleepVal = if ($DcSleep) { $DcSleep.DCSettingIndex } else { 1 }

$AcSleepColor = if ($AcSleepVal -eq 0) { "Green" } else { "Red" }
$DcSleepColor = if ($DcSleepVal -eq 0) { "Green" } else { "Red" }

Write-Host "    - Standby Sleep State (Plugged In) Setting: $AcSleepVal (Required = 0 [Disabled])" -ForegroundColor $AcSleepColor
Write-Host "    - Standby Sleep State (On Battery) Setting: $DcSleepVal (Required = 0 [Disabled])" -ForegroundColor $DcSleepColor

# 2. Audit BitLocker Settings
$FvePath = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
$DmaLock = Get-ItemProperty -Path $FvePath -Name "DisableExternalDMAUnderLock" -ErrorAction SilentlyContinue
$DmaLockVal = if ($DmaLock) { $DmaLock.DisableExternalDMAUnderLock } else { 0 }
$DmaLockColor = if ($DmaLockVal -eq 1) { "Green" } else { "Red" }

$FvePolicyPath = "HKLM:\System\CurrentControlSet\Policies\Microsoft\FVE"
$UsbWrite = Get-ItemProperty -Path $FvePolicyPath -Name "RDVDenyWriteAccess" -ErrorAction SilentlyContinue
$UsbWriteVal = if ($UsbWrite) { $UsbWrite.RDVDenyWriteAccess } else { 0 }
$UsbWriteColor = if ($UsbWriteVal -eq 1) { "Green" } else { "Red" }

Write-Host "    - Disable DMA Under Lock: $DmaLockVal (Required = 1)" -ForegroundColor $DmaLockColor
Write-Host "    - USB Unencrypted Write Block: $UsbWriteVal (Required = 1)" -ForegroundColor $UsbWriteColor

# 3. Audit Device Restriction Settings
$RestrictPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions"
$DenyDev = Get-ItemProperty -Path $RestrictPath -Name "DenyDeviceClasses" -ErrorAction SilentlyContinue
$DenyDevVal = if ($DenyDev) { $DenyDev.DenyDeviceClasses } else { 0 }
$DenyDevColor = if ($DenyDevVal -eq 1) { "Green" } else { "Red" }

$DenyID = Get-ItemProperty -Path $RestrictPath -Name "DenyDeviceIDs" -ErrorAction SilentlyContinue
$DenyIDVal = if ($DenyID) { $DenyID.DenyDeviceIDs } else { 0 }
$DenyIDColor = if ($DenyIDVal -eq 1) { "Green" } else { "Red" }

Write-Host "    - Prevent Device Setup Class Installation: $DenyDevVal (Required = 1)" -ForegroundColor $DenyDevColor
Write-Host "    - Prevent Device ID Installation: $DenyIDVal (Required = 1)" -ForegroundColor $DenyIDColor

$DenyClassPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceClasses"
$Sbp2 = Get-ItemProperty -Path $DenyClassPath -Name "1" -ErrorAction SilentlyContinue
$Sbp2Val = if ($Sbp2) { $Sbp2."1" } else { "" }
$Sbp2Color = if ($Sbp2Val -eq "{d48179be-ec20-11d1-b6b8-00c04fa372a7}") { "Green" } else { "Red" }

Write-Host "    - Blocked SBP-2 Setup Class: '$Sbp2Val' (Required = '{d48179be-ec20-11d1-b6b8-00c04fa372a7}')" -ForegroundColor $Sbp2Color

$DenyIDPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceIDs"
$DId1 = Get-ItemProperty -Path $DenyIDPath -Name "1" -ErrorAction SilentlyContinue
$DId1Val = if ($DId1) { $DId1."1" } else { "" }
$DId1Color = if ($DId1Val -eq "PCI\CC_0C0A") { "Green" } else { "Red" }

$DId2 = Get-ItemProperty -Path $DenyIDPath -Name "2" -ErrorAction SilentlyContinue
$DId2Val = if ($DId2) { $DId2."2" } else { "" }
$DId2Color = if ($DId2Val -eq "PCI\CC_0C0010") { "Green" } else { "Red" }

Write-Host "    - Blocked Device ID PCI\CC_0C0A: '$DId1Val' (Required = 'PCI\CC_0C0A')" -ForegroundColor $DId1Color
Write-Host "    - Blocked Device ID PCI\CC_0C0010: '$DId2Val' (Required = 'PCI\CC_0C0010')" -ForegroundColor $DId2Color

# 4. Audit Kernel DMA Protection Setting
$KDmaPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\KernelDMAProtection"
$EnumPol = Get-ItemProperty -Path $KDmaPath -Name "DeviceEnumerationPolicy" -ErrorAction SilentlyContinue
$EnumPolVal = if ($EnumPol) { $EnumPol.DeviceEnumerationPolicy } else { 2 }
$EnumPolColor = if ($EnumPolVal -eq 0) { "Green" } else { "Red" }

Write-Host "    - Kernel DMA Protection Policy: $EnumPolVal (Required = 0 [Block all])" -ForegroundColor $EnumPolColor
