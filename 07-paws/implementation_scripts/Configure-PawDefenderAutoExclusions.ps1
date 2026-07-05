# Configure-PawDefenderAutoExclusions.ps1
$ExclPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions"
if (-not (Test-Path $ExclPath)) { New-Item -Path $ExclPath -Force | Out-Null }
Set-ItemProperty -Path $ExclPath -Name "DisableAutoExclusions" -Value 0 -Type DWord -Force
