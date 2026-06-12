# Test-WSUSClientStatus.ps1
# Audits registry values to verify WSUS server assignment and Delivery Optimization configuration.

Write-Host "--- Auditing WSUS Client Settings ---" -ForegroundColor Cyan

$WUPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
$WUAUPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
$DOPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization"

$WUServerProp = Get-ItemProperty -Path $WUPath -Name "WUServer" -ErrorAction SilentlyContinue
$WUStatusProp = Get-ItemProperty -Path $WUPath -Name "WUStatusServer" -ErrorAction SilentlyContinue
$UseWUServerProp = Get-ItemProperty -Path $WUAUPath -Name "UseWUServer" -ErrorAction SilentlyContinue

$WUServerVal = if ($WUServerProp) { $WUServerProp.WUServer } else { "" }
$WUStatusVal = if ($WUStatusProp) { $WUStatusProp.WUStatusServer } else { "" }
$UseWUVal = if ($UseWUServerProp) { $UseWUServerProp.UseWUServer } else { 0 }

$ServerColor = if ($WUServerVal -like "http*") { "Green" } else { "Red" }
$UseColor = if ($UseWUVal -eq 1) { "Green" } else { "Red" }

Write-Host "    - Intranet WUServer: $WUServerVal" -ForegroundColor $ServerColor
Write-Host "    - Intranet WUStatusServer: $WUStatusVal" -ForegroundColor $ServerColor
Write-Host "    - UseWUServer Active: $UseWUVal (Required = 1)" -ForegroundColor $UseColor

# Audit Delivery Optimization
$DOVal = if (Test-Path $DOPath) { (Get-ItemProperty -Path $DOPath -Name "DODownloadMode" -ErrorAction SilentlyContinue).DODownloadMode } else { $null }
$DOColor = if ($DOVal -eq 2) { "Green" } else { "Red" }
Write-Host "    - Delivery Optimization DODownloadMode: $($DOVal | Out-String).Trim() (Expected = 2)" -ForegroundColor $DOColor
