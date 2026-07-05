# Configure-DisableOneDriveSync.ps1
$Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive"
if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
Set-ItemProperty -Path $Path -Name "DisableFileSyncNGSC" -Value 1 -Type DWord -Force
