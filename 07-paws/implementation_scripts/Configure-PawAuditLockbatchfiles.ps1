# Configure-PawAuditLockbatchfiles.ps1
Write-Host "Enforcing System Mitigation control: lock-batch-files..." -ForegroundColor Cyan

# Set Registry value: LockBatchFilesWhenInUse
if (-not (Test-Path "HKLM:\SOFTWARE\Microsoft\Command Processor")) { New-Item -Path "HKLM:\SOFTWARE\Microsoft\Command Processor" -Force | Out-Null }
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Command Processor" -Name "LockBatchFilesWhenInUse" -Value 1 -Type DWord -Force
Write-Host "    Enforced LockBatchFilesWhenInUse = 1" -ForegroundColor Green


