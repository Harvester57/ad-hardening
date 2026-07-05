# Configure-EndAuditProtectedroots.ps1
Write-Host "Enforcing System Mitigation control: protected-roots..." -ForegroundColor Cyan

# Set Registry value: Flags
if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\Root\ProtectedRoots")) { New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\Root\ProtectedRoots" -Force | Out-Null }
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\Root\ProtectedRoots" -Name "Flags" -Value 1 -Type DWord -Force
Write-Host "    Enforced Flags = 1" -ForegroundColor Green


