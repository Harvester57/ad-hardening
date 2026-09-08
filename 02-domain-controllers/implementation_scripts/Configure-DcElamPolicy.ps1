# Configure-DcElamPolicy.ps1
# Description: Configures the Early Launch Antimalware (ELAM) boot-start driver initialization policy on Domain Controllers.

Write-Host "Applying ELAM Boot-Start driver initialization policy on Domain Controller..." -ForegroundColor Cyan

$ElamPath = "HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch"
if (-not (Test-Path $ElamPath)) {
    New-Item -Path $ElamPath -Force | Out-Null
}

Set-ItemProperty -Path $ElamPath -Name "DriverLoadPolicy" -Value 3 -Type DWord -ErrorAction Stop
Write-Host "[+] ELAM Boot-Start driver initialization policy set to 'Good, unknown and bad but critical' (Value = 3)." -ForegroundColor Green
