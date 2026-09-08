# Configure-EndKerberosArmoring.ps1
# Description: Configures client-side Kerberos Armoring (FAST) and certificate device authentication on Tier 2 client endpoints.

Write-Host "Applying hardening requirement: Enable Kerberos Armoring on Tier 2 Endpoints..." -ForegroundColor Cyan

$ClientRegPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"

if (-not (Test-Path $ClientRegPath)) {
    New-Item -Path $ClientRegPath -Force | Out-Null
}

# 1. Enable Kerberos client support for claims and armoring
Set-ItemProperty -Path $ClientRegPath -Name "EnableCbacAndArmor" -Value 1 -Type DWord

# 2. Support device authentication using certificate (Automatic)
Set-ItemProperty -Path $ClientRegPath -Name "DevicePKInitEnabled" -Value 1 -Type DWord
Set-ItemProperty -Path $ClientRegPath -Name "DevicePKInitBehavior" -Value 0 -Type DWord

# 3. Ensure RequireFast is set to 0 (Opportunistic negotiation for general client workstations)
Set-ItemProperty -Path $ClientRegPath -Name "RequireFast" -Value 0 -Type DWord

Write-Host "Client endpoint Kerberos Armoring configured successfully." -ForegroundColor Green
