# Configure-PawAsrOfficeWin32Calls.ps1
$AsrRulesPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
if (-not (Test-Path $AsrRulesPath)) { New-Item -Path $AsrRulesPath -Force | Out-Null }
Set-ItemProperty -Path $AsrRulesPath -Name "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b" -Value "1" -Type String -Force
