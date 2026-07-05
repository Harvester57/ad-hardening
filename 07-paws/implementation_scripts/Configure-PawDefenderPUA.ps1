# Configure-PawDefenderPUA.ps1
Set-MpPreference -PUAProtection 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "PUAProtection" -Value 1 -Type DWord -Force
