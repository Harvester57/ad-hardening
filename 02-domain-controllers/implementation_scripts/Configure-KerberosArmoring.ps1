# Configure-KerberosArmoring.ps1
# Description: Configures Kerberos Armoring (FAST) and PKInit Freshness Extension registry settings on Domain Controllers and Kerberos clients.

Write-Host "Applying hardening requirement: Enable Kerberos Armoring (FAST) on Domain Controllers..." -ForegroundColor Cyan

$ClientRegPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"
$KdcRegPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\KDC\Parameters"

# Configure client-side settings (applicable to all systems, including DCs for DC-to-DC authentication)
if (-not (Test-Path $ClientRegPath)) {
    New-Item -Path $ClientRegPath -Force | Out-Null
}
Set-ItemProperty -Path $ClientRegPath -Name "EnableCbacAndArmor" -Value 1 -Type DWord
Set-ItemProperty -Path $ClientRegPath -Name "DevicePKInitEnabled" -Value 1 -Type DWord
Set-ItemProperty -Path $ClientRegPath -Name "DevicePKInitBehavior" -Value 0 -Type DWord
Write-Host "Client-side Kerberos Armoring and Device Certificate Authentication enabled successfully." -ForegroundColor Green

# Determine if the host is a Domain Controller
$DomainRole = (Get-CimInstance -ClassName Win32_ComputerSystem).DomainRole
$IsDC = ($DomainRole -eq 4) -or ($DomainRole -eq 5)

if ($IsDC) {
    Write-Host "Domain Controller detected. Enabling KDC support for Kerberos Armoring and PKInit Freshness..." -ForegroundColor Cyan
    if (-not (Test-Path $KdcRegPath)) {
        New-Item -Path $KdcRegPath -Force | Out-Null
    }
    
    # Value 1 = Supported (Safe deployment baseline)
    # Value 3 = Fail unarmored authentication requests (Strict/Enforced state)
    Set-ItemProperty -Path $KdcRegPath -Name "EnableCbacAndArmor" -Value 1 -Type DWord
    Set-ItemProperty -Path $KdcRegPath -Name "CbacAndArmorLevel" -Value 1 -Type DWord
    # Value 1 = Supported for PKInit Freshness Extension (RFC 8070)
    Set-ItemProperty -Path $KdcRegPath -Name "PKINITFreshness" -Value 1 -Type DWord
    Write-Host "KDC support for claims, armoring (Supported: 1), and PKInit Freshness enabled successfully." -ForegroundColor Green
}
