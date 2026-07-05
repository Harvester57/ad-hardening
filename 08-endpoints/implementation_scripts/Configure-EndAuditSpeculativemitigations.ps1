# Configure-EndAuditSpeculativemitigations.ps1
Write-Host "Enforcing System Mitigation control: speculative-mitigations..." -ForegroundColor Cyan

# Set Registry value: FeatureSettingsOverride
if (-not (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management")) { New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Force | Out-Null }
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "FeatureSettingsOverride" -Value 72 -Type DWord -Force
Write-Host "    Enforced FeatureSettingsOverride = 72" -ForegroundColor Green

# Set Registry value: FeatureSettingsOverrideMask
if (-not (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management")) { New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Force | Out-Null }
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "FeatureSettingsOverrideMask" -Value 3 -Type DWord -Force
Write-Host "    Enforced FeatureSettingsOverrideMask = 3" -ForegroundColor Green


