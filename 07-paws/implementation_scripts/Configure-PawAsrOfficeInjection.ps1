# Configure-PawAsrOfficeInjection.ps1
$AsrRulesPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
if (-not (Test-Path $AsrRulesPath)) { New-Item -Path $AsrRulesPath -Force | Out-Null }
Set-ItemProperty -Path $AsrRulesPath -Name "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84" -Value "1" -Type String -Force
