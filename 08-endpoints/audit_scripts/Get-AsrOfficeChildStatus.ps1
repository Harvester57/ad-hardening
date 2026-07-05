# Get-AsrOfficeChildStatus.ps1
$AsrRulesPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
$Value = Get-ItemProperty -Path $AsrRulesPath -Name "d4f940ab-401b-4efc-aadc-ad5f3c50688a" -ErrorAction SilentlyContinue
if ($Value -and ($Value."d4f940ab-401b-4efc-aadc-ad5f3c50688a" -eq "1" -or $Value."d4f940ab-401b-4efc-aadc-ad5f3c50688a" -eq 1)) {
    Write-Output "Compliant"
    exit 0
} else {
    Write-Output "Non-Compliant"
    exit 1
}
