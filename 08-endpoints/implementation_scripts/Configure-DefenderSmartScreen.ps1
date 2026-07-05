# Configure-DefenderSmartScreen.ps1
$Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
Set-ItemProperty -Path $Path -Name "EnableSmartScreen" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $Path -Name "ShellSmartScreenLevel" -Value "Block" -Type String -Force
