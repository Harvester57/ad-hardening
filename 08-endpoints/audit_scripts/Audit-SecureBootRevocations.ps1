# Audit-SecureBootRevocations.ps1
# Description: Queries UEFI Secure Boot parameters and audits BlackLotus mitigation registry settings.

Write-Host "--- Auditing BlackLotus Mitigations ---" -ForegroundColor Cyan

$script:NonCompliant = $false

# 1. Audit AvailableUpdates registry key
$Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Secureboot"
if (Test-Path $Path) {
    $Val = Get-ItemProperty -Path $Path -Name "AvailableUpdates" -ErrorAction SilentlyContinue
    $UpdateVal = if ($Val) { $Val.AvailableUpdates } else { 0 }
    
    # Check if configured (>= 0x4000 / 16384)
    if ($UpdateVal -ge 16384) {
        Write-Host "    - BlackLotus Revocation Updates (AvailableUpdates): $UpdateVal (Compliant)" -ForegroundColor Green
    } else {
        Write-Host "    - BlackLotus Revocation Updates (AvailableUpdates): $UpdateVal (Non-Compliant - DBX/SVN revocations not triggered)" -ForegroundColor Red
        $script:NonCompliant = $true
    }
} else {
    Write-Host "    - BlackLotus Revocation Updates: Registry path not found (Non-Compliant)" -ForegroundColor Red
    $script:NonCompliant = $true
}

# 2. Audit UEFICA2023Status (if present)
$ServicingPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing"
if (Test-Path $ServicingPath) {
    $ServVal = Get-ItemProperty -Path $ServicingPath -Name "UEFICA2023Status" -ErrorAction SilentlyContinue
    if ($ServVal) {
        $Status = $ServVal.UEFICA2023Status
        $Color = if ($Status -eq "Updated") { "Green" } else { "Yellow" }
        Write-Host "    - UEFI CA 2023 Update Status: $Status" -ForegroundColor $Color
    }
}

if ($script:NonCompliant) {
    exit 1
}
