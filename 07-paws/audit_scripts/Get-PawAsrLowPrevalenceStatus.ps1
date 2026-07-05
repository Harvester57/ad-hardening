# Get-PawAsrLowPrevalenceStatus.ps1
$AsrRulesPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
$Value = Get-ItemProperty -Path $AsrRulesPath -Name "01443614-cd74-433a-b99e-2ecdc07bfc25" -ErrorAction SilentlyContinue
if ($Value -and ($Value."01443614-cd74-433a-b99e-2ecdc07bfc25" -eq "1" -or $Value."01443614-cd74-433a-b99e-2ecdc07bfc25" -eq 1)) {
    Write-Output "Compliant"
    exit 0
} else {
    Write-Output "Non-Compliant"
    exit 1
}
