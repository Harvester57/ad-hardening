# Configure-DisableLltdMapperIoDriver.ps1
# Description: Disables the LLTD Mapper I/O (LLTDIO) driver policy on Domain Controllers.

Write-Host "Disabling LLTD Mapper I/O (LLTDIO) Driver..." -ForegroundColor Cyan

$LltdPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD"
if (-not (Test-Path -Path $LltdPath)) {
    New-Item -Path $LltdPath -Force | Out-Null
}

Set-ItemProperty -Path $LltdPath -Name "AllowLLTDIOOnDomain" -Value 0 -Type DWord -ErrorAction Stop
Set-ItemProperty -Path $LltdPath -Name "AllowLLTDIOOnPublicNet" -Value 0 -Type DWord -ErrorAction Stop
Set-ItemProperty -Path $LltdPath -Name "EnableLLTDIO" -Value 0 -Type DWord -ErrorAction Stop
Set-ItemProperty -Path $LltdPath -Name "ProhibitLLTDIOOnPrivateNet" -Value 0 -Type DWord -ErrorAction Stop

Write-Host "LLTD Mapper I/O Driver disabled successfully." -ForegroundColor Green
