# Disable-DcWsh.ps1
# Description: Disables Windows Script Host globally across 64-bit and 32-bit registry hives, enforces TrustPolicy, and remaps script file associations to Notepad on Domain Controllers.

Write-Host "Applying Windows Script Host and file association hardening for Domain Controllers..." -ForegroundColor Cyan

# 1. Disable WSH globally in 64-bit HKLM
$RegistryHklm = "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings"
if (-not (Test-Path $RegistryHklm)) {
    New-Item -Path $RegistryHklm -Force | Out-Null
}
Set-ItemProperty -Path $RegistryHklm -Name "Enabled" -Value 0 -Type DWord -Force
Set-ItemProperty -Path $RegistryHklm -Name "TrustPolicy" -Value 2 -Type DWord -Force
Write-Host "[+] WSH globally disabled and TrustPolicy enforced in HKLM." -ForegroundColor Green

# 2. Disable WSH in WOW6432Node on 64-bit systems
if ([Environment]::Is64BitOperatingSystem) {
    $RegistryWow64 = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows Script Host\Settings"
    if (-not (Test-Path $RegistryWow64)) {
        New-Item -Path $RegistryWow64 -Force | Out-Null
    }
    Set-ItemProperty -Path $RegistryWow64 -Name "Enabled" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path $RegistryWow64 -Name "TrustPolicy" -Value 2 -Type DWord -Force
    Write-Host "[+] WSH globally disabled and TrustPolicy enforced in HKLM WOW6432Node." -ForegroundColor Green
}

# 3. Disable WSH in current user HKCU hive
$RegistryHkcu = "HKCU:\SOFTWARE\Microsoft\Windows Script Host\Settings"
if (-not (Test-Path $RegistryHkcu)) {
    New-Item -Path $RegistryHkcu -Force | Out-Null
}
Set-ItemProperty -Path $RegistryHkcu -Name "Enabled" -Value 0 -Type DWord -Force
Set-ItemProperty -Path $RegistryHkcu -Name "TrustPolicy" -Value 2 -Type DWord -Force
Write-Host "[+] WSH disabled in current user HKCU hive." -ForegroundColor Green

# 4. Remap script file extensions to notepad
$Extensions = @("vbs", "vbe", "js", "jse", "wsf", "wsh", "hta")
foreach ($Ext in $Extensions) {
    $ProgIdPath = "HKLM:\SOFTWARE\Classes\.$Ext"
    
    # Update Class Association to Notepad
    if (-not (Test-Path $ProgIdPath)) {
        New-Item -Path $ProgIdPath -Force | Out-Null
    }
    Set-ItemProperty -Path $ProgIdPath -Name "" -Value "txtfile" -Type String -Force
    Write-Host "    Mapped .$Ext extension to txtfile handler." -ForegroundColor Gray
}
Write-Host "[+] Script file extension handlers mapped to Notepad." -ForegroundColor Green
Write-Host "[i] Note: Software Licensing Management Tool (slmgr.vbs) requires ADBA or KMS. Use Get-CimInstance SoftwareLicensingProduct for querying status." -ForegroundColor Yellow
