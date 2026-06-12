# Audit-HardwareSecurityFeatures.ps1
# Description: Audits TPM 2.0, CPU Virtualization, and IOMMU/DMA status.

Write-Host "--- Auditing Hardware Security Features ---" -ForegroundColor Cyan

# 1. Audit TPM 2.0 Status
$Tpm = Get-Tpm -ErrorAction SilentlyContinue
if ($Tpm) {
    if ($Tpm.TpmPresent -eq $true) {
        $TpmColor = "Red"
        if ($Tpm.TpmReady -eq $true) {
            $TpmColor = "Green"
        }
        Write-Host "Status: TPM Present: $($Tpm.TpmPresent) | Ready: $($Tpm.TpmReady)" -ForegroundColor $TpmColor
    } else {
        Write-Host "VULNERABLE: TPM 2.0 is not detected on this system." -ForegroundColor Red
    }
} else {
    Write-Host "VULNERABLE: TPM verification cmdlet failed." -ForegroundColor Red
}

# 2. Audit VBS and DMA Status via Win32_DeviceGuard
try {
    $DG = Get-CimInstance -Namespace "Root\Microsoft\Windows\DeviceGuard" -ClassName "Win32_DeviceGuard" -ErrorAction Stop
    
    # VirtualizationBasedSecurityStatus: 2 = Running
    $VbsStatus = $DG.VirtualizationBasedSecurityStatus
    $VbsColor = "Red"
    if ($VbsStatus -eq 2) {
        $VbsColor = "Green"
    }
    Write-Host "Status: Virtualization-Based Security Status: $($VbsStatus) (Required = 2 [Running])" -ForegroundColor $VbsColor
    
    # AvailableSecurityProperties: 3 = DMA Protection (IOMMU)
    $DmaSupported = $DG.AvailableSecurityProperties -contains 3
    $DmaColor = "Red"
    if ($DmaSupported -eq $true) {
        $DmaColor = "Green"
    }
    Write-Host "Status: Hardware IOMMU/DMA Protection: $($DmaSupported)" -ForegroundColor $DmaColor
    
    # RequiredSecurityProperties: 3 = DMA Protection enforced
    $DmaEnforced = $DG.RequiredSecurityProperties -contains 3
    $EnforcedColor = "Red"
    if ($DmaEnforced -eq $true) {
        $EnforcedColor = "Green"
    }
    Write-Host "Status: DMA Protection Policy Enforced: $($DmaEnforced)" -ForegroundColor $EnforcedColor
    
} catch {
    Write-Host "VULNERABLE: Win32_DeviceGuard WMI class could not be queried. VBS is likely inactive." -ForegroundColor Red
}
