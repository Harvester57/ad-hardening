# Configure-DisableLltdResponderDriver.ps1
# Description: Disables the LLTD Responder (RSPNDR) driver policy on Domain Controllers.

Write-Host "Disabling LLTD Responder (RSPNDR) Driver..." -ForegroundColor Cyan

$LltdPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD"
if (-not (Test-Path -Path $LltdPath)) {
    New-Item -Path $LltdPath -Force | Out-Null
}

Set-ItemProperty -Path $LltdPath -Name "AllowRspndrOnDomain" -Value 0 -Type DWord -ErrorAction Stop
Set-ItemProperty -Path $LltdPath -Name "AllowRspndrOnPublicNet" -Value 0 -Type DWord -ErrorAction Stop
Set-ItemProperty -Path $LltdPath -Name "EnableRspndr" -Value 0 -Type DWord -ErrorAction Stop
Set-ItemProperty -Path $LltdPath -Name "ProhibitRspndrOnPrivateNet" -Value 0 -Type DWord -ErrorAction Stop

Write-Host "LLTD Responder Driver disabled successfully." -ForegroundColor Green
