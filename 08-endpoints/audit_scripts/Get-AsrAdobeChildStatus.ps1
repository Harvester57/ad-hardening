# Get-AsrAdobeChildStatus.ps1
$AsrRulesPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
$Value = Get-ItemProperty -Path $AsrRulesPath -Name "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c" -ErrorAction SilentlyContinue
if ($Value -and ($Value."7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c" -eq "1" -or $Value."7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c" -eq 1)) {
    Write-Output "Compliant"
    exit 0
} else {
    Write-Output "Non-Compliant"
    exit 1
}
