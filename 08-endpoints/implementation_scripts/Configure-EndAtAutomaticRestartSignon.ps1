#Configure-EndAtAutomaticRestartSignon.ps1
# Description: Configures Administrative Templates: Disable Windows Automatic Restart Sign-On (ARSO).

Write-Host "Configuring Administrative Templates: Disable Windows Automatic Restart Sign-On (ARSO)..." -ForegroundColor Cyan

if (-not (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System")) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableAutomaticRestartSignOn" -Value 1 -Type DWord -Force

Write-Host "[+] Administrative Templates: Disable Windows Automatic Restart Sign-On (ARSO) applied successfully." -ForegroundColor Green
