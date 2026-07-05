# Audit-PawSecureBootRevocations.ps1
# Description: Queries UEFI Secure Boot parameters and audits BlackLotus mitigation registry settings.

Write-Host "--- Auditing BlackLotus Mitigations ---" -ForegroundColor Cyan

$script:NonCompliant = $false

# Audit AvailableUpdates registry key
$Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Secureboot"
if (Test-Path $Path) {
    $Val = Get-ItemProperty -Path $Path -Name "AvailableUpdates" -ErrorAction SilentlyContinue
    $UpdateVal = if ($Val) { $Val.AvailableUpdates } else { 0 }
    
    # Check if at least DBX update (64) is enabled
    if ($UpdateVal -ge 64) {
        Write-Host "    - BlackLotus Revocation Updates (AvailableUpdates): $UpdateVal (Compliant)" -ForegroundColor Green
    } else {
        Write-Host "    - BlackLotus Revocation Updates (AvailableUpdates): $UpdateVal (Non-Compliant - DBX/SVN revocations not triggered)" -ForegroundColor Red
        $script:NonCompliant = $true
    }
} else {
    Write-Host "    - BlackLotus Revocation Updates: Registry path not found (Non-Compliant)" -ForegroundColor Red
    $script:NonCompliant = $true
}

if ($script:NonCompliant) {
    exit 1
}
