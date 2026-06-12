# Enable-VBSCredentialGuard.ps1
# Configures local registry keys to activate VBS and Credential Guard.

Write-Host "--- Enforcing VBS & Credential Guard ---" -ForegroundColor Cyan

$DeviceGuardPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"

if (-not (Test-Path $DeviceGuardPath)) {
    New-Item -Path $DeviceGuardPath -Force | Out-Null
}

# Enable Virtualization-Based Security (VBS)
Set-ItemProperty -Path $DeviceGuardPath -Name "EnableVirtualizationBasedSecurity" -Value 1 -Type DWord
# RequirePlatformSecurityFeatures = 3 (Secure Boot and DMA Protection)
Set-ItemProperty -Path $DeviceGuardPath -Name "RequirePlatformSecurityFeatures" -Value 3 -Type DWord
# HypervisorEnforcedCodeIntegrity = 1 (HVCI / Memory Integrity Enabled)
Set-ItemProperty -Path $DeviceGuardPath -Name "HypervisorEnforcedCodeIntegrity" -Value 1 -Type DWord
# LsaCfgFlags = 1 (Credential Guard Enabled with UEFI Lock)
Set-ItemProperty -Path $DeviceGuardPath -Name "LsaCfgFlags" -Value 1 -Type DWord
# ConfigureSystemGuardLaunch = 1 (Secure Launch Enabled)
Set-ItemProperty -Path $DeviceGuardPath -Name "ConfigureSystemGuardLaunch" -Value 1 -Type DWord
# HVCIMATRequired = 1 (Require UEFI Memory Attributes Table)
Set-ItemProperty -Path $DeviceGuardPath -Name "HVCIMATRequired" -Value 1 -Type DWord

Write-Host "[+] VBS and Credential Guard registry settings applied. (Reboot required)." -ForegroundColor Green
