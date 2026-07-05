# Get-DcAsrLsassDumpStatus.ps1
$AsrRulesPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
$Value = Get-ItemProperty -Path $AsrRulesPath -Name "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" -ErrorAction SilentlyContinue
if ($Value -and ($Value."9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" -eq "1" -or $Value."9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" -eq 1)) {
    Write-Output "Compliant"
    exit 0
} else {
    Write-Output "Non-Compliant"
    exit 1
}
