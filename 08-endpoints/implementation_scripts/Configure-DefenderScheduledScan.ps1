# Configure-DefenderScheduledScan.ps1
Set-MpPreference -DisableEmailScanning $false
Set-MpPreference -DisableHeuristics $false
$ScanPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan"
if (-not (Test-Path $ScanPath)) { New-Item -Path $ScanPath -Force | Out-Null }
Set-ItemProperty -Path $ScanPath -Name "ScheduleDay" -Value 0 -Type DWord -Force
Set-ItemProperty -Path $ScanPath -Name "DisableEmailScanning" -Value 0 -Type DWord -Force
Set-ItemProperty -Path $ScanPath -Name "DisableHeuristics" -Value 0 -Type DWord -Force
Set-ItemProperty -Path $ScanPath -Name "DaysWithoutCatchupQuickScan" -Value 7 -Type DWord -Force
