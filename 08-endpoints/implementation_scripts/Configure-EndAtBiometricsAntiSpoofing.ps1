#Configure-EndAtBiometricsAntiSpoofing.ps1
# Description: Configures Administrative Templates: Configure Biometrics Enhanced Anti-Spoofing.

Write-Host "Configuring Administrative Templates: Configure Biometrics Enhanced Anti-Spoofing..." -ForegroundColor Cyan

if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures" -Name "EnhancedAntiSpoofing" -Value 1 -Type DWord -Force

Write-Host "[+] Administrative Templates: Configure Biometrics Enhanced Anti-Spoofing applied successfully." -ForegroundColor Green
