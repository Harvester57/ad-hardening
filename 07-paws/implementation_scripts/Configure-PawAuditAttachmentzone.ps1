# Configure-PawAuditAttachmentzone.ps1
Write-Host "Enforcing System Mitigation control: attachment-zone..." -ForegroundColor Cyan

# Set Registry value: SaveZoneInformation
if (-not (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments")) { New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Force | Out-Null }
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "SaveZoneInformation" -Value 2 -Type DWord -Force
Write-Host "    Enforced SaveZoneInformation = 2" -ForegroundColor Green


