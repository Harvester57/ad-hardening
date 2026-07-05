# Configure-AsrAdobeChild.ps1
$AsrRulesPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
if (-not (Test-Path $AsrRulesPath)) { New-Item -Path $AsrRulesPath -Force | Out-Null }
Set-ItemProperty -Path $AsrRulesPath -Name "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c" -Value "1" -Type String -Force
