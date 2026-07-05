# Configure-DefenderFileHash.ps1
Set-MpPreference -EnableFileHashComputation $true
$MpEnginePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine"
if (-not (Test-Path $MpEnginePath)) { New-Item -Path $MpEnginePath -Force | Out-Null }
Set-ItemProperty -Path $MpEnginePath -Name "EnableFileHashComputation" -Value 1 -Type DWord -Force
