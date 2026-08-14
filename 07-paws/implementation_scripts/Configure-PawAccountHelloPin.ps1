# Configure-PawAccountHelloPin.ps1
Write-Host "Configuring PAW Windows Hello for Business and PIN policies..." -ForegroundColor Cyan

# 1. System Logon PIN Policy
$SysPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
if (-not (Test-Path $SysPath)) { New-Item -Path $SysPath -Force | Out-Null }
Set-ItemProperty -Path $SysPath -Name "AllowDomainPINLogon" -Value 0 -Type DWord -Force

# 2. PIN Complexity
$PinPath = "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork\PINComplexity"
if (-not (Test-Path $PinPath)) { New-Item -Path $PinPath -Force | Out-Null }
Set-ItemProperty -Path $PinPath -Name "MinimumPINLength" -Value 6 -Type DWord -Force

# 3. Hardware Security Device
$PfwPath = "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork"
if (-not (Test-Path $PfwPath)) { New-Item -Path $PfwPath -Force | Out-Null }
Set-ItemProperty -Path $PfwPath -Name "RequireSecurityDevice" -Value 1 -Type DWord -Force

$TpmPath = "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork\ExcludeSecurityDevices"
if (-not (Test-Path $TpmPath)) { New-Item -Path $TpmPath -Force | Out-Null }
Set-ItemProperty -Path $TpmPath -Name "TPM12" -Value 0 -Type DWord -Force

# 4. MSA Optional
$SysPolPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
if (-not (Test-Path $SysPolPath)) { New-Item -Path $SysPolPath -Force | Out-Null }
Set-ItemProperty -Path $SysPolPath -Name "MSAOptional" -Value 1 -Type DWord -Force

Write-Host "Windows Hello and PIN policies applied." -ForegroundColor Green
