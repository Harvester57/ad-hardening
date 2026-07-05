# Configure-DefenderMapsOverride.ps1
$SpynetPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet"
if (-not (Test-Path $SpynetPath)) { New-Item -Path $SpynetPath -Force | Out-Null }
Set-ItemProperty -Path $SpynetPath -Name "LocalSettingOverrideSpynetReporting" -Value 0 -Type DWord -Force
