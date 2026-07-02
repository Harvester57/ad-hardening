# Disable-Wsh.ps1
# Description: Disables Windows Script Host globally in HKLM and HKCU registry hives, and remaps script file associations to Notepad.

Write-Host "Applying Windows Script Host and file association hardening..." -ForegroundColor Cyan

# 1. Disable WSH globally
$RegistryHklm = "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings"
if (-not (Test-Path $RegistryHklm)) {
    New-Item -Path $RegistryHklm -Force | Out-Null
}
Set-ItemProperty -Path $RegistryHklm -Name "Enabled" -Value 0 -Type DWord -Force
Write-Host "[+] WSH globally disabled in HKLM." -ForegroundColor Green

$RegistryHkcu = "HKCU:\SOFTWARE\Microsoft\Windows Script Host\Settings"
if (-not (Test-Path $RegistryHkcu)) {
    New-Item -Path $RegistryHkcu -Force | Out-Null
}
Set-ItemProperty -Path $RegistryHkcu -Name "Enabled" -Value 0 -Type DWord -Force
Write-Host "[+] WSH disabled in current user HKCU hive." -ForegroundColor Green

# 2. Remap script file extensions to notepad
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
