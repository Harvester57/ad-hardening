# Configure-EndAccountAnonymousRestrictions.ps1
# Description: Hardens anonymous access, SAM enumeration, PKU2U, and subsystem object naming on Endpoints.

Write-Host "Configuring Endpoint anonymous access and enumeration restrictions..." -ForegroundColor Cyan

$LsaPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
if (-not (Test-Path -Path $LsaPath)) {
    New-Item -Path $LsaPath -Force | Out-Null
}
Set-ItemProperty -Path $LsaPath -Name "RestrictAnonymousSAM" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $LsaPath -Name "RestrictAnonymous" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $LsaPath -Name "ObaseCaseInsensitive" -Value 1 -Type DWord -Force

$KerbPath = "HKLM:\System\CurrentControlSet\Control\Lsa\Kerberos\Parameters"
if (-not (Test-Path $KerbPath)) {
    New-Item -Path $KerbPath -Force | Out-Null
}
Set-ItemProperty -Path $KerbPath -Name "AllowPKU2U" -Value 0 -Type DWord -Force

Write-Host "Anonymous access and enumeration restrictions applied successfully." -ForegroundColor Green
