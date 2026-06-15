# Set-WMIStaticPort.ps1
# Description: Configures WMI to run in a standalone host process on static TCP port 24158 with packet privacy.

Write-Host "Applying hardening requirement: Configure WMI Static Port..." -ForegroundColor Cyan

# 1. Configure the static TCP port 24158 for WMI AppID
$WmiAppIdPath = "HKLM:\SOFTWARE\Classes\AppID\{8BC3F05E-D86B-11D0-A075-00C04FB68820}"
if (-not (Test-Path $WmiAppIdPath)) {
    New-Item -Path $WmiAppIdPath -Force | Out-Null
}
# Set Endpoints string array
Set-ItemProperty -Path $WmiAppIdPath -Name "Endpoints" -Value @("ncacn_ip_tcp,0,24158") -Type MultiString
Write-Host "[+] Configured WMI AppID static endpoint to TCP 24158." -ForegroundColor Green

# 2. Configure WMI to run in a standalone host process with packet privacy
# This command sets HKLM\SYSTEM\CurrentControlSet\Services\winmgmt\Type to OWN_PROCESS (16)
# and configures the default authentication level to PKT_PRIVACY (6).
Write-Host "[+] Configuring WMI service to run as standalone process..." -ForegroundColor Gray
$Proc = Start-Process -FilePath "winmgmt.exe" -ArgumentList "/standalonehost 6" -Wait -NoNewWindow -PassThru

if ($Proc.ExitCode -eq 0) {
    Write-Host "[+] WMI standalone host configuration completed successfully." -ForegroundColor Green
} else {
    Write-Warning "[-] WMI standalone host configuration exited with code $($Proc.ExitCode)."
}

Write-Host "[!] Note: A system reboot is recommended to cleanly apply WMI process changes and restart all dependencies." -ForegroundColor Yellow
