# Audit-UEFISecurity.ps1
# Description: Audits local boot environment and BIOS firmware properties.

Write-Host "--- Auditing UEFI Security Baseline ---" -ForegroundColor Cyan

# 1. Verify boot environment type
$RegPath = "HKLM:\System\CurrentControlSet\Control"
$FirmwareProperty = Get-ItemProperty -Path $RegPath -Name "PEFirmwareType" -ErrorAction SilentlyContinue

if ($FirmwareProperty) {
    $FirmwareValue = $FirmwareProperty.PEFirmwareType
    if ($FirmwareValue -eq 2) {
        Write-Host "Status: Native UEFI mode is active." -ForegroundColor Green
    } else {
        Write-Host "VULNERABLE: System booted in Legacy BIOS mode (CSM enabled). Value: $($FirmwareValue)" -ForegroundColor Red
    }
} else {
    Write-Host "VULNERABLE: Boot environment type could not be read from registry." -ForegroundColor Red
}

# 2. Audit Secure Boot status
try {
    $SecureBootActive = Confirm-SecureBootUEFI -ErrorAction Stop
    if ($SecureBootActive -eq $true) {
        Write-Host "Status: UEFI Secure Boot is enabled." -ForegroundColor Green
    } else {
        Write-Host "VULNERABLE: UEFI Secure Boot is supported but disabled in firmware." -ForegroundColor Red
    }
} catch [System.PlatformNotSupportedException] {
    Write-Host "VULNERABLE: UEFI Secure Boot is not supported on this platform." -ForegroundColor Red
} catch {
    Write-Host "VULNERABLE: UEFI Secure Boot validation failed. Error: $($_.Exception.Message)" -ForegroundColor Red
}

# 3. Retrieve BIOS details
$BiosDetails = Get-CimInstance -ClassName Win32_Bios -ErrorAction SilentlyContinue
if ($BiosDetails) {
    Write-Host "Firmware Manufacturer: $($BiosDetails.Manufacturer)" -ForegroundColor White
    Write-Host "Firmware Version: $($BiosDetails.SMBIOSBIOSVersion)" -ForegroundColor White
    Write-Host "Firmware Release Date: $($BiosDetails.ReleaseDate)" -ForegroundColor White
} else {
    Write-Host "Warning: BIOS details could not be retrieved via WMI." -ForegroundColor Yellow
}
