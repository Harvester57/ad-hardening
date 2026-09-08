# Set-UEFISecurity.ps1
# Description: Configures OS-level boot parameters and audits OEM firmware configuration for endpoints and member servers.

Write-Host "--- Configuring Endpoint UEFI & Boot Security Baseline ---" -ForegroundColor Cyan

# 1. Disable Windows Fast Startup (forces full cold boot and fresh TPM PCR measurements)
$PowerPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power"
if (-not (Test-Path $PowerPath)) {
    New-Item -Path $PowerPath -Force | Out-Null
}

try {
    Set-ItemProperty -Path $PowerPath -Name "HiberbootEnabled" -Value 0 -Type DWord -Force -ErrorAction Stop
    Write-Host "[+] Windows Fast Startup disabled (HiberbootEnabled = 0)." -ForegroundColor Green
} catch {
    Write-Host "[!] Failed to configure HiberbootEnabled: $($_.Exception.Message)" -ForegroundColor Red
}

# 2. Configure Device Guard Platform Security Flags
$DeviceGuardPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"
if (-not (Test-Path $DeviceGuardPath)) {
    New-Item -Path $DeviceGuardPath -Force | Out-Null
}

try {
    # 1 = Secure Boot, 3 = Secure Boot and DMA Protection
    Set-ItemProperty -Path $DeviceGuardPath -Name "RequirePlatformSecurityFeatures" -Value 1 -Type DWord -Force -ErrorAction Stop
    Write-Host "[+] Device Guard required platform security features configured (Value = 1)." -ForegroundColor Green
} catch {
    Write-Host "[!] Failed to configure RequirePlatformSecurityFeatures: $($_.Exception.Message)" -ForegroundColor Red
}

# 3. Detect Hardware OEM and report vendor tooling commands
$Bios = Get-CimInstance -ClassName Win32_Bios -ErrorAction SilentlyContinue
Write-Host "`nOEM Firmware Detection:" -ForegroundColor Cyan
Write-Host "  Manufacturer: $($Bios.Manufacturer)" -ForegroundColor White
Write-Host "  BIOS Version: $($Bios.SMBIOSBIOSVersion)" -ForegroundColor White

if ($Bios.Manufacturer -match "Dell") {
    Write-Host "  [i] Dell Platform detected. Enterprise configuration via Dell Command | PowerShell Provider:" -ForegroundColor Yellow
    Write-Host "      Import-Module DellBIOSProvider" -ForegroundColor Gray
    Write-Host "      Set-Item -Path DellSmbios:\Boot\BootMode 'UEFI'" -ForegroundColor Gray
    Write-Host "      Set-Item -Path DellSmbios:\SecureBoot\SecureBoot 'Enabled'" -ForegroundColor Gray
    Write-Host "      Set-Item -Path DellSmbios:\VirtualizationSupport\Virtualization 'Enabled'" -ForegroundColor Gray
    Write-Host "      Set-Item -Path DellSmbios:\VirtualizationSupport\VtForDirectIO 'Enabled'" -ForegroundColor Gray
} elseif ($Bios.Manufacturer -match "HP") {
    Write-Host "  [i] HP Platform detected. Enterprise configuration via HP Client Management Script Library (HPCMSL):" -ForegroundColor Yellow
    Write-Host "      Import-Module HPCMSL" -ForegroundColor Gray
    Write-Host "      Set-HPBIOSSettingValue -Name 'Boot Mode' -Value 'UEFI Native (without CSM)'" -ForegroundColor Gray
    Write-Host "      Set-HPBIOSSettingValue -Name 'Secure Boot' -Value 'Enable'" -ForegroundColor Gray
    Write-Host "      Set-HPBIOSSettingValue -Name 'Virtualization Technology' -Value 'Enable'" -ForegroundColor Gray
} elseif ($Bios.Manufacturer -match "Lenovo") {
    Write-Host "  [i] Lenovo Platform detected. Enterprise configuration via Lenovo BIOS WMI interface:" -ForegroundColor Yellow
    Write-Host "      (gwmi -class Lenovo_SetBiosSetting -namespace root\wmi).SetBiosSetting('BootMode,UEFI')" -ForegroundColor Gray
    Write-Host "      (gwmi -class Lenovo_SetBiosSetting -namespace root\wmi).SetBiosSetting('SecureBoot,Enable')" -ForegroundColor Gray
}

Write-Host "`n[+] Remediation script completed." -ForegroundColor Green
