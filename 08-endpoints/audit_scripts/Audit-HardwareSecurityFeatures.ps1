# Audit-HardwareSecurityFeatures.ps1
# Description: Audits Kernel DMA Protection registry policy, hardware IOMMU/DMA status, VBS state, and TPM readiness.

Write-Host "--- Auditing Kernel DMA Protection and Hardware Security Baseline ---" -ForegroundColor Cyan

# 1. Audit Kernel DMA Protection Registry Policy
$RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\KernelDMAProtection"
$EnumPolicy = Get-ItemProperty -Path $RegPath -Name "DeviceEnumerationPolicy" -ErrorAction SilentlyContinue

if ($null -ne $EnumPolicy -and $EnumPolicy.DeviceEnumerationPolicy -eq 0) {
    Write-Host "Status: Kernel DMA Protection Policy (DeviceEnumerationPolicy): 0 (Block All) [COMPLIANT]" -ForegroundColor Green
} else {
    $CurrentVal = if ($null -ne $EnumPolicy) { $EnumPolicy.DeviceEnumerationPolicy } else { "Not Configured" }
    Write-Host "VULNERABLE: Kernel DMA Protection Policy is '$($CurrentVal)'. Expected: 0 (Block All)." -ForegroundColor Red
}

# 2. Audit VBS and Hardware DMA/IOMMU Status via Win32_DeviceGuard
try {
    $DG = Get-CimInstance -Namespace "Root\Microsoft\Windows\DeviceGuard" -ClassName "Win32_DeviceGuard" -ErrorAction Stop
    
    # VirtualizationBasedSecurityStatus: 2 = Running
    $VbsStatus = $DG.VirtualizationBasedSecurityStatus
    if ($VbsStatus -eq 2) {
        Write-Host "Status: Virtualization-Based Security (VBS) Status: 2 (Running) [COMPLIANT]" -ForegroundColor Green
    } else {
        Write-Host "VULNERABLE: Virtualization-Based Security (VBS) is not running (Status: $($VbsStatus))." -ForegroundColor Red
    }
    
    # AvailableSecurityProperties: 3 = DMA Protection (IOMMU)
    $DmaSupported = $DG.AvailableSecurityProperties -contains 3
    if ($DmaSupported -eq $true) {
        Write-Host "Status: Hardware IOMMU / DMA Remapping Support: True [COMPLIANT]" -ForegroundColor Green
    } else {
        Write-Host "VULNERABLE: Hardware IOMMU / DMA Protection is not available on this platform." -ForegroundColor Red
    }
    
    # RequiredSecurityProperties: 3 = DMA Protection enforced
    $DmaEnforced = $DG.RequiredSecurityProperties -contains 3
    if ($DmaEnforced -eq $true) {
        Write-Host "Status: DMA Protection Security Policy Enforced: True [COMPLIANT]" -ForegroundColor Green
    } else {
        Write-Host "Status: DMA Protection Security Policy Enforced: False [INFO]" -ForegroundColor Yellow
    }
} catch {
    Write-Host "VULNERABLE: Win32_DeviceGuard WMI class could not be queried. VBS / Device Guard is inactive." -ForegroundColor Red
}

# 3. Audit TPM 2.0 Status
$Tpm = Get-Tpm -ErrorAction SilentlyContinue
if ($null -ne $Tpm) {
    if ($Tpm.TpmPresent -eq $true -and $Tpm.TpmReady -eq $true) {
        Write-Host "Status: TPM 2.0 Present: True | Ready: True [COMPLIANT]" -ForegroundColor Green
    } else {
        Write-Host "VULNERABLE: TPM Present: $($Tpm.TpmPresent) | Ready: $($Tpm.TpmReady) (Expected: Present and Ready)." -ForegroundColor Red
    }
} else {
    Write-Host "VULNERABLE: TPM verification cmdlet failed." -ForegroundColor Red
}
