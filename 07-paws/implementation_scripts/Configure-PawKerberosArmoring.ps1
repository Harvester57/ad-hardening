# Configure-PawKerberosArmoring.ps1
# Description: Configures Kerberos Armoring (FAST) with strict enforcement and certificate device authentication on PAWs.

Write-Host "Applying hardening requirement: Enable Kerberos Armoring (FAST) on PAWs..." -ForegroundColor Cyan

$ClientRegPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"

if (-not (Test-Path $ClientRegPath)) {
    New-Item -Path $ClientRegPath -Force | Out-Null
}

# 1. Enable Kerberos client support for claims and armoring
Set-ItemProperty -Path $ClientRegPath -Name "EnableCbacAndArmor" -Value 1 -Type DWord

# 2. Support device authentication using certificate (Automatic)
Set-ItemProperty -Path $ClientRegPath -Name "DevicePKInitEnabled" -Value 1 -Type DWord
Set-ItemProperty -Path $ClientRegPath -Name "DevicePKInitBehavior" -Value 0 -Type DWord

# 3. Fail authentication requests when Kerberos armoring is not available (Strict FAST enforcement on Tier 0 PAWs)
Set-ItemProperty -Path $ClientRegPath -Name "RequireFast" -Value 1 -Type DWord

Write-Host "PAW Kerberos Armoring configured successfully with strict enforcement (RequireFast = 1)." -ForegroundColor Green
