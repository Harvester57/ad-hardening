#Configure-PawAtAppxDeploymentRestrictions.ps1
# Description: Configures Administrative Templates: App Package Deployment Restrictions for PAWs.

Write-Host "Configuring Administrative Templates: App Package Deployment Restrictions for PAWs..." -ForegroundColor Cyan

if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Appx")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Appx" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Appx" -Name "DisablePerUserUnsignedPackagesByDefault" -Value 1 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Appx" -Name "BlockNonAdminUserInstall" -Value 1 -Type DWord -Force

Write-Host "[+] Administrative Templates: App Package Deployment Restrictions for PAWs applied successfully." -ForegroundColor Green
