# Configure-CredentialGuard.ps1
# Description: Enables Virtualization-Based Security (VBS) and Credential Guard in the registry.

Write-Host "Applying hardening requirement: Enable Credential Guard and VBS Baseline..." -ForegroundColor Cyan

# 1. Enable Virtualization-Based Security and related hypervisor options
$vbsPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"
if (-not (Test-Path $vbsPath)) {
    New-Item -Path $vbsPath -Force | Out-Null
}

$vbsSettings = @{
    "EnableVirtualizationBasedSecurity" = 1
    "HVCIMATRequired"                   = 1
    "ConfigureSystemGuardLaunch"        = 1
    "RequirePlatformSecurityFeatures"   = 1
    "HypervisorEnforcedCodeIntegrity"   = 1
}

foreach ($Setting in $vbsSettings.Keys) {
    Set-ItemProperty -Path $vbsPath -Name $Setting -Value $vbsSettings[$Setting] -Type DWord -ErrorAction Stop
}
Write-Host "Virtualization-Based Security parameters enabled in registry." -ForegroundColor Green

# 2. Configure Credential Guard (LsaCfgFlags: 1 = UEFI Lock, 2 = No UEFI Lock)
$lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
if (-not (Test-Path $lsaPath)) {
    New-Item -Path $lsaPath -Force | Out-Null
}
Set-ItemProperty -Path $lsaPath -Name "LsaCfgFlags" -Value 1 -Type DWord
Write-Host "Credential Guard configured with UEFI lock in registry." -ForegroundColor Green

Write-Host "Hardening applied successfully. A system reboot is required." -ForegroundColor Green
