# Configure-DcAsrVulnerableDrivers.ps1
$AsrRulesPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
if (-not (Test-Path $AsrRulesPath)) { New-Item -Path $AsrRulesPath -Force | Out-Null }
Set-ItemProperty -Path $AsrRulesPath -Name "56a863a9-875e-4185-98a7-b882c64b5ce5" -Value "1" -Type String -Force
