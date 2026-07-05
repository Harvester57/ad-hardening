# Configure-DefenderFamilyLockdown.ps1
$FamilyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Family options"
if (-not (Test-Path $FamilyPath)) { New-Item -Path $FamilyPath -Force | Out-Null }
Set-ItemProperty -Path $FamilyPath -Name "UILockdown" -Value 1 -Type DWord -Force
