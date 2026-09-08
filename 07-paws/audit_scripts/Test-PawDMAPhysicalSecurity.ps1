# Test-PawDMAPhysicalSecurity.ps1
# Description: Audits local registry configuration for standby settings, wake password, DMA protection under lock, USB restrictions, and blocked device classes/IDs on PAWs.

Write-Host "--- Auditing PAW DMA and Physical Security ---" -ForegroundColor Cyan
$isCompliant = $true

# 1. Audit Standby Settings
$SleepPath = "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab"
$AcSleep = Get-ItemProperty -Path $SleepPath -Name "ACSettingIndex" -ErrorAction SilentlyContinue
$DcSleep = Get-ItemProperty -Path $SleepPath -Name "DCSettingIndex" -ErrorAction SilentlyContinue

$AcSleepVal = if ($AcSleep) { $AcSleep.ACSettingIndex } else { 1 }
$DcSleepVal = if ($DcSleep) { $DcSleep.DCSettingIndex } else { 1 }

$AcSleepColor = if ($AcSleepVal -eq 0) { "Green" } else { $isCompliant = $false; "Red" }
$DcSleepColor = if ($DcSleepVal -eq 0) { "Green" } else { $isCompliant = $false; "Red" }

Write-Host "    - Standby Sleep State (Plugged In) Setting: $($AcSleepVal) (Required = 0 [Disabled])" -ForegroundColor $AcSleepColor
Write-Host "    - Standby Sleep State (On Battery) Setting: $($DcSleepVal) (Required = 0 [Disabled])" -ForegroundColor $DcSleepColor

# 2. Audit Wake Password Requirement
$WakePath = "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51"
$AcWake = Get-ItemProperty -Path $WakePath -Name "ACSettingIndex" -ErrorAction SilentlyContinue
$DcWake = Get-ItemProperty -Path $WakePath -Name "DCSettingIndex" -ErrorAction SilentlyContinue

$AcWakeVal = if ($AcWake) { $AcWake.ACSettingIndex } else { 0 }
$DcWakeVal = if ($DcWake) { $DcWake.DCSettingIndex } else { 0 }

$AcWakeColor = if ($AcWakeVal -eq 1) { "Green" } else { $isCompliant = $false; "Red" }
$DcWakeColor = if ($DcWakeVal -eq 1) { "Green" } else { $isCompliant = $false; "Red" }

Write-Host "    - Wake Password Required (Plugged In): $($AcWakeVal) (Required = 1 [Enabled])" -ForegroundColor $AcWakeColor
Write-Host "    - Wake Password Required (On Battery): $($DcWakeVal) (Required = 1 [Enabled])" -ForegroundColor $DcWakeColor

# 3. Audit BitLocker Settings
$FvePath = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
$DmaLock = Get-ItemProperty -Path $FvePath -Name "DisableExternalDMAUnderLock" -ErrorAction SilentlyContinue
$DmaLockVal = if ($DmaLock) { $DmaLock.DisableExternalDMAUnderLock } else { 0 }
$DmaLockColor = if ($DmaLockVal -eq 1) { "Green" } else { $isCompliant = $false; "Red" }

$CrossOrg = Get-ItemProperty -Path $FvePath -Name "RDVDenyCrossOrg" -ErrorAction SilentlyContinue
$CrossOrgVal = if ($CrossOrg) { $CrossOrg.RDVDenyCrossOrg } else { 1 }
$CrossOrgColor = if ($CrossOrgVal -eq 0) { "Green" } else { $isCompliant = $false; "Red" }

$FvePolicyPath = "HKLM:\System\CurrentControlSet\Policies\Microsoft\FVE"
$UsbWrite = Get-ItemProperty -Path $FvePolicyPath -Name "RDVDenyWriteAccess" -ErrorAction SilentlyContinue
$UsbWriteVal = if ($UsbWrite) { $UsbWrite.RDVDenyWriteAccess } else { 0 }
$UsbWriteColor = if ($UsbWriteVal -eq 1) { "Green" } else { $isCompliant = $false; "Red" }

Write-Host "    - Disable DMA Under Lock: $($DmaLockVal) (Required = 1)" -ForegroundColor $DmaLockColor
Write-Host "    - USB Deny Cross Org Removable Drives: $($CrossOrgVal) (Required = 0)" -ForegroundColor $CrossOrgColor
Write-Host "    - USB Unencrypted Write Block: $($UsbWriteVal) (Required = 1)" -ForegroundColor $UsbWriteColor

# 4. Audit Device Restriction Settings
$RestrictPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions"
$DenyDev = Get-ItemProperty -Path $RestrictPath -Name "DenyDeviceClasses" -ErrorAction SilentlyContinue
$DenyDevVal = if ($DenyDev) { $DenyDev.DenyDeviceClasses } else { 0 }
$DenyDevColor = if ($DenyDevVal -eq 1) { "Green" } else { $isCompliant = $false; "Red" }

$DenyId = Get-ItemProperty -Path $RestrictPath -Name "DenyDeviceIDs" -ErrorAction SilentlyContinue
$DenyIdVal = if ($DenyId) { $DenyId.DenyDeviceIDs } else { 0 }
$DenyIdColor = if ($DenyIdVal -eq 1) { "Green" } else { $isCompliant = $false; "Red" }

Write-Host "    - Prevent Device Setup Class Installation: $($DenyDevVal) (Required = 1)" -ForegroundColor $DenyDevColor
Write-Host "    - Prevent Device ID Installation: $($DenyIdVal) (Required = 1)" -ForegroundColor $DenyIdColor

$DenyClassPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceClasses"
$Sbp2 = Get-ItemProperty -Path $DenyClassPath -Name "1" -ErrorAction SilentlyContinue
$Sbp2Val = if ($Sbp2) { $Sbp2."1" } else { "" }
$Sbp2Color = if ($Sbp2Val -eq "{d48179be-ec20-11d1-b6b8-00c04fa372a7}") { "Green" } else { $isCompliant = $false; "Red" }

$Host1394 = Get-ItemProperty -Path $DenyClassPath -Name "2" -ErrorAction SilentlyContinue
$Host1394Val = if ($Host1394) { $Host1394."2" } else { "" }
$Host1394Color = if ($Host1394Val -eq "{6bdd1fc1-810f-11d0-bec7-08002be2092f}") { "Green" } else { $isCompliant = $false; "Red" }

Write-Host "    - Blocked SBP-2 Setup Class: '$($Sbp2Val)' (Required = '{d48179be-ec20-11d1-b6b8-00c04fa372a7}')" -ForegroundColor $Sbp2Color
Write-Host "    - Blocked 1394 Host Setup Class: '$($Host1394Val)' (Required = '{6bdd1fc1-810f-11d0-bec7-08002be2092f}')" -ForegroundColor $Host1394Color

$DenyIdPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceIDs"
$DId1 = Get-ItemProperty -Path $DenyIdPath -Name "1" -ErrorAction SilentlyContinue
$DId1Val = if ($DId1) { $DId1."1" } else { "" }
$DId1Color = if ($DId1Val -eq "PCI\CC_0C0A") { "Green" } else { $isCompliant = $false; "Red" }

$DId2 = Get-ItemProperty -Path $DenyIdPath -Name "2" -ErrorAction SilentlyContinue
$DId2Val = if ($DId2) { $DId2."2" } else { "" }
$DId2Color = if ($DId2Val -eq "PCI\CC_0C0010") { "Green" } else { $isCompliant = $false; "Red" }

$DId3 = Get-ItemProperty -Path $DenyIdPath -Name "3" -ErrorAction SilentlyContinue
$DId3Val = if ($DId3) { $DId3."3" } else { "" }
$DId3Color = if ($DId3Val -eq "PCI\CC_0607") { "Green" } else { $isCompliant = $false; "Red" }

$DId4 = Get-ItemProperty -Path $DenyIdPath -Name "4" -ErrorAction SilentlyContinue
$DId4Val = if ($DId4) { $DId4."4" } else { "" }
$DId4Color = if ($DId4Val -eq "PCI\CC_0605") { "Green" } else { $isCompliant = $false; "Red" }

Write-Host "    - Blocked Device ID PCI\CC_0C0A: '$($DId1Val)' (Required = 'PCI\CC_0C0A')" -ForegroundColor $DId1Color
Write-Host "    - Blocked Device ID PCI\CC_0C0010: '$($DId2Val)' (Required = 'PCI\CC_0C0010')" -ForegroundColor $DId2Color
Write-Host "    - Blocked Device ID PCI\CC_0607: '$($DId3Val)' (Required = 'PCI\CC_0607')" -ForegroundColor $DId3Color
Write-Host "    - Blocked Device ID PCI\CC_0605: '$($DId4Val)' (Required = 'PCI\CC_0605')" -ForegroundColor $DId4Color

# 5. Audit Kernel DMA Protection Setting (Stricter for PAWs)
$KDmaPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\KernelDMAProtection"
$EnumPol = Get-ItemProperty -Path $KDmaPath -Name "DeviceEnumerationPolicy" -ErrorAction SilentlyContinue
$EnumPolVal = if ($EnumPol) { $EnumPol.DeviceEnumerationPolicy } else { 2 }
$EnumPolColor = if ($EnumPolVal -eq 0) { "Green" } else { $isCompliant = $false; "Red" }

Write-Host "    - Kernel DMA Protection Policy: $($EnumPolVal) (Required = 0 [Block all])" -ForegroundColor $EnumPolColor

# 6. Final Compliance Assessment
if ($isCompliant) {
    Write-Host "[+] Audit Result: SECURE - PAW DMA and physical security controls are fully compliant." -ForegroundColor Green
} else {
    Write-Host "[-] Audit Result: VULNERABLE - One or more PAW DMA or physical security settings do not meet baseline requirements." -ForegroundColor Red
}
