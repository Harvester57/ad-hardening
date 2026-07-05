# Configure-DefenderDisableGenericReports.ps1
$Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
Set-ItemProperty -Path $Path -Name "DisableGenericRePorts" -Value 1 -Type DWord -Force
