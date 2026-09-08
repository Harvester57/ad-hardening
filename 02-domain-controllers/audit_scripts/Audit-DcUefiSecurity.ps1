# Audit-DcUefiSecurity.ps1
# Description: Audits local boot environment, Secure Boot, TPM, and virtualization properties on Domain Controllers.

Write-Host "--- Auditing UEFI Security Baseline on Domain Controller ---" -ForegroundColor Cyan

$script:Vulnerable = $false

# 1. Verify Boot Environment Type (Native UEFI)
$FirmwareType = $env:firmware_type
$RegPath = "HKLM:\System\CurrentControlSet\Control"
$FirmwareProperty = Get-ItemProperty -Path $RegPath -Name "PEFirmwareType" -ErrorAction SilentlyContinue

if ($FirmwareProperty -and $FirmwareProperty.PEFirmwareType -eq 2) {
    Write-Host "  [+] Boot Mode: Native UEFI active (PEFirmwareType = 2)." -ForegroundColor Green
} elseif ($FirmwareType -eq "UEFI") {
    Write-Host "  [+] Boot Mode: Native UEFI active (firmware_type = UEFI)." -ForegroundColor Green
} else {
    Write-Host "  [!] VULNERABLE: System booted in Legacy BIOS mode (CSM enabled) or unrecognized firmware type." -ForegroundColor Red
    $script:Vulnerable = $true
}

# 2. Audit UEFI Secure Boot Status
try {
    $SecureBootActive = Confirm-SecureBootUEFI -ErrorAction Stop
    if ($SecureBootActive -eq $true) {
        Write-Host "  [+] Secure Boot: Enabled in firmware." -ForegroundColor Green
    } else {
        Write-Host "  [!] VULNERABLE: Secure Boot is supported but currently disabled in firmware." -ForegroundColor Red
        $script:Vulnerable = $true
    }
} catch [System.PlatformNotSupportedException] {
    Write-Host "  [!] VULNERABLE: UEFI Secure Boot is not supported on this platform." -ForegroundColor Red
    $script:Vulnerable = $true
} catch {
    Write-Host "  [!] VULNERABLE: UEFI Secure Boot validation failed: $($_.Exception.Message)" -ForegroundColor Red
    $script:Vulnerable = $true
}

# 3. Audit TPM 2.0 Status
try {
    $Tpm = Get-Tpm -ErrorAction Stop
    if ($Tpm.TpmPresent -and $Tpm.TpmReady) {
        Write-Host "  [+] TPM 2.0: Present and Ready (Enabled: $($Tpm.TpmEnabled), Activated: $($Tpm.TpmActivated))." -ForegroundColor Green
    } else {
        Write-Host "  [!] VULNERABLE: TPM is not present, not ready, or disabled in firmware." -ForegroundColor Red
        $script:Vulnerable = $true
    }
} catch {
    Write-Host "  [!] VULNERABLE: Failed to query TPM status: $($_.Exception.Message)" -ForegroundColor Red
    $script:Vulnerable = $true
}

# 4. Audit CPU Virtualization Extensions in Firmware
$Processor = Get-CimInstance -ClassName Win32_Processor -ErrorAction SilentlyContinue | Select-Object -First 1
if ($Processor -and $Processor.VirtualizationFirmwareEnabled -eq $true) {
    Write-Host "  [+] Hardware Virtualization: Enabled in firmware (VT-x / AMD-V)." -ForegroundColor Green
} else {
    # If Hyper-V/VBS is already running, VirtualizationFirmwareEnabled may report false inside partition
    $Vbs = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard -ErrorAction SilentlyContinue
    if ($Vbs -and $Vbs.VirtualizationBasedSecurityStatus -ge 1) {
        Write-Host "  [+] Hardware Virtualization: Verified active via running Virtualization-Based Security." -ForegroundColor Green
    } else {
        Write-Host "  [!] VULNERABLE: Hardware CPU virtualization extensions are disabled in firmware." -ForegroundColor Red
        $script:Vulnerable = $true
    }
}

# 5. Audit Windows Fast Startup Configuration
$PowerReg = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -ErrorAction SilentlyContinue
if ($PowerReg -and $PowerReg.HiberbootEnabled -eq 0) {
    Write-Host "  [+] Windows Fast Startup: Disabled (Full cold boot enforced)." -ForegroundColor Green
} else {
    Write-Host "  [!] VULNERABLE: Windows Fast Startup is enabled (HiberbootEnabled != 0). Must be disabled for deterministic boot measurements." -ForegroundColor Red
    $script:Vulnerable = $true
}

# 6. Retrieve Server & BIOS Firmware Specifications
$ComputerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
$BiosDetails = Get-CimInstance -ClassName Win32_Bios -ErrorAction SilentlyContinue

Write-Host "  Platform Model:        $($ComputerSystem.Model)" -ForegroundColor White
if ($BiosDetails) {
    Write-Host "  Firmware Manufacturer: $($BiosDetails.Manufacturer)" -ForegroundColor White
    Write-Host "  Firmware Version:      $($BiosDetails.SMBIOSBIOSVersion)" -ForegroundColor White
    Write-Host "  Firmware Release Date: $($BiosDetails.ReleaseDate)" -ForegroundColor White
} else {
    Write-Host "  Warning: BIOS details could not be retrieved via WMI." -ForegroundColor Yellow
}

# Final Verdict
if ($script:Vulnerable) {
    Write-Host "Audit Result: VULNERABLE" -ForegroundColor Red
    exit 1
} else {
    Write-Host "Audit Result: SECURE" -ForegroundColor Green
    exit 0
}
