# Configure-PawAuditCertpadding.ps1
Write-Host "Enforcing System Mitigation control: cert-padding..." -ForegroundColor Cyan

# Set Registry value: EnableCertPaddingCheck
if (-not (Test-Path "HKLM:\Software\Microsoft\Cryptography\Wintrust\Config")) { New-Item -Path "HKLM:\Software\Microsoft\Cryptography\Wintrust\Config" -Force | Out-Null }
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Cryptography\Wintrust\Config" -Name "EnableCertPaddingCheck" -Value 1 -Type DWord -Force
Write-Host "    Enforced EnableCertPaddingCheck = 1" -ForegroundColor Green

# Set Registry value: EnableCertPaddingCheck
if (-not (Test-Path "HKLM:\Software\Wow6432Node\Microsoft\Cryptography\Wintrust\Config")) { New-Item -Path "HKLM:\Software\Wow6432Node\Microsoft\Cryptography\Wintrust\Config" -Force | Out-Null }
Set-ItemProperty -Path "HKLM:\Software\Wow6432Node\Microsoft\Cryptography\Wintrust\Config" -Name "EnableCertPaddingCheck" -Value 1 -Type DWord -Force
Write-Host "    Enforced EnableCertPaddingCheck = 1" -ForegroundColor Green


