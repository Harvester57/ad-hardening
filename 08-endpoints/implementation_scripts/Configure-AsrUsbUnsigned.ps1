# Configure-AsrUsbUnsigned.ps1
$AsrRulesPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
if (-not (Test-Path $AsrRulesPath)) { New-Item -Path $AsrRulesPath -Force | Out-Null }
Set-ItemProperty -Path $AsrRulesPath -Name "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4" -Value "1" -Type String -Force
