# Get-PawAsrUsbUnsignedStatus.ps1
$AsrRulesPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
$Value = Get-ItemProperty -Path $AsrRulesPath -Name "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4" -ErrorAction SilentlyContinue
if ($Value -and ($Value."b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4" -eq "1" -or $Value."b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4" -eq 1)) {
    Write-Output "Compliant"
    exit 0
} else {
    Write-Output "Non-Compliant"
    exit 1
}
