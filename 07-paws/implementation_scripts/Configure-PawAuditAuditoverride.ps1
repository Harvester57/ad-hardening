# Configure-PawAuditAuditoverride.ps1
Write-Host "Applying Audit Policy category: audit-override..." -ForegroundColor Cyan

# Set Registry Override: SCENoApplyLegacyAuditPolicy
if (-not (Test-Path "reg:\HKLM\System\CurrentControlSet\Control\Lsa")) { New-Item -Path "reg:\HKLM\System\CurrentControlSet\Control\Lsa" -Force | Out-Null }
Set-ItemProperty -Path "reg:\HKLM\System\CurrentControlSet\Control\Lsa" -Name "SCENoApplyLegacyAuditPolicy" -Value 1 -Type DWord -Force
Write-Host "    Enforced SCENoApplyLegacyAuditPolicy = 1" -ForegroundColor Green

# Set Registry Override: LogLevel
if (-not (Test-Path "reg:\HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters")) { New-Item -Path "reg:\HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters" -Force | Out-Null }
Set-ItemProperty -Path "reg:\HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters" -Name "LogLevel" -Value 0 -Type DWord -Force
Write-Host "    Enforced LogLevel = 0" -ForegroundColor Green


