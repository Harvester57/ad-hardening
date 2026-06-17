# Set-PawWSUSClientConfiguration.ps1
# Description: Configures local registry keys to point the Windows Update client to the intranet WSUS server and enforces DO Group mode on PAWs.

Write-Host "--- Configuring WSUS Client Settings ---" -ForegroundColor Cyan

$WUPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
$WUAUPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
$DOPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization"

# 1. Create keys if they do not exist
if (-not (Test-Path $WUPath)) {
    New-Item -Path $WUPath -Force | Out-Null
}
if (-not (Test-Path $WUAUPath)) {
    New-Item -Path $WUAUPath -Force | Out-Null
}
if (-not (Test-Path $DOPath)) {
    New-Item -Path $DOPath -Force | Out-Null
}

# Define intranet WSUS URL
$WSUSServer = "http://local-wsus.domain.local:8530"

# 2. Configure update location and statistics server
Set-ItemProperty -Path $WUPath -Name "WUServer" -Value $WSUSServer -Type String -Force
Set-ItemProperty -Path $WUPath -Name "WUStatusServer" -Value $WSUSServer -Type String -Force
Set-ItemProperty -Path $WUPath -Name "DoNotConnectToWindowsUpdateInternetLocations" -Value 1 -Type DWord -Force

# 3. Configure Automatic Updates behavior (AUOptions = 4: Auto Download & Schedule)
Set-ItemProperty -Path $WUAUPath -Name "NoAutoUpdate" -Value 0 -Type DWord -Force
Set-ItemProperty -Path $WUAUPath -Name "AUOptions" -Value 4 -Type DWord -Force
Set-ItemProperty -Path $WUAUPath -Name "UseWUServer" -Value 1 -Type DWord -Force

# 4. Enforce DODownloadMode = 2 (Group)
Set-ItemProperty -Path $DOPath -Name "DODownloadMode" -Value 2 -Type DWord -Force

Write-Host "[+] Local WSUS parameters and Delivery Optimization download mode applied." -ForegroundColor Green
