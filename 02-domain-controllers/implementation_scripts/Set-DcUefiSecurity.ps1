# Set-DcUefiSecurity.ps1
# Description: Configures OS-level boot parameters and audits platform firmware configuration on Domain Controllers.

Write-Host "--- Configuring Domain Controller UEFI & Boot Security Baseline ---" -ForegroundColor Cyan

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

# 3. Detect Server Environment (Physical vs Virtual)
$ComputerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
$Bios = Get-CimInstance -ClassName Win32_Bios -ErrorAction SilentlyContinue

Write-Host "`nPlatform Environment Detection:" -ForegroundColor Cyan
Write-Host "  Model:        $($ComputerSystem.Model)" -ForegroundColor White
Write-Host "  Manufacturer: $($Bios.Manufacturer)" -ForegroundColor White
Write-Host "  BIOS Version: $($Bios.SMBIOSBIOSVersion)" -ForegroundColor White

if ($ComputerSystem.Model -match "Virtual Machine|VMware|KVM|Hyper-V") {
    Write-Host "  [i] Virtual Domain Controller detected." -ForegroundColor Yellow
    Write-Host "      Ensure VM is Generation 2 (UEFI) with Secure Boot enabled and a virtual TPM (vTPM 2.0) attached." -ForegroundColor Gray
    Write-Host "      Hyper-V PowerShell: Set-VMFirmware -VMName '<DC>' -EnableSecureBoot On -SecureBootTemplate MicrosoftWindows" -ForegroundColor Gray
    Write-Host "      Hyper-V PowerShell: Enable-VMTPM -VMName '<DC>'" -ForegroundColor Gray
} else {
    Write-Host "  [i] Physical Bare-Metal Server detected." -ForegroundColor Yellow
    Write-Host "      Ensure BIOS supervisor password is set, CSM is disabled, boot order is locked to RAID," -ForegroundColor Gray
    Write-Host "      VT-x/VT-d is enabled, and Out-of-Band BMC (iDRAC/iLO) has IPMI over LAN disabled." -ForegroundColor Gray
}

Write-Host "`n[+] Remediation script completed." -ForegroundColor Green
