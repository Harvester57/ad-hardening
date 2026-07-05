# Audit-DcSecureBoot.ps1
# Description: Queries UEFI Secure Boot parameters and audits UEFI Secure Boot status.

Write-Host "--- Auditing UEFI Secure Boot ---" -ForegroundColor Cyan

$script:NonCompliant = $false

# 1. Verify boot environment type
if ($env:firmware_type -eq "UEFI") {
    Write-Host "    - Boot Environment Type: UEFI" -ForegroundColor Green
} else {
    Write-Host "    - VULNERABLE: System booted in Legacy BIOS mode (CSM enabled) or firmware type is unrecognized." -ForegroundColor Red
    $script:NonCompliant = $true
}

# 2. Verify Secure Boot status
try {
    # Confirm-SecureBootUEFI returns $true if Secure Boot is active, $false if disabled,
    # and throws an exception if the platform does not support UEFI or Secure Boot.
    $SecureBootState = Confirm-SecureBootUEFI -ErrorAction Stop
    
    $Color = if ($SecureBootState -eq $true) { "Green" } else { "Red" }
    Write-Host "    - Secure Boot Active: $SecureBootState" -ForegroundColor $Color
    if ($SecureBootState -eq $false) { $script:NonCompliant = $true }
} catch [System.PlatformNotSupportedException] {
    Write-Host "    - VULNERABLE: UEFI Secure Boot is not supported on this platform (Legacy BIOS mode)." -ForegroundColor Red
    $script:NonCompliant = $true
} catch {
    # If cmdlet throws unauthorized access or not enabled error
    Write-Host "    - VULNERABLE: Secure Boot is disabled in firmware or cannot be verified. Error: $($_.Exception.Message)" -ForegroundColor Red
    $script:NonCompliant = $true
}

if ($script:NonCompliant) {
    exit 1
}
