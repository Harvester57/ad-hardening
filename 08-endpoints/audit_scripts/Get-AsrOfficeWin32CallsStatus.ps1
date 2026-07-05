# Get-AsrOfficeWin32CallsStatus.ps1
$AsrRulesPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
$Value = Get-ItemProperty -Path $AsrRulesPath -Name "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b" -ErrorAction SilentlyContinue
if ($Value -and ($Value."92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b" -eq "1" -or $Value."92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b" -eq 1)) {
    Write-Output "Compliant"
    exit 0
} else {
    Write-Output "Non-Compliant"
    exit 1
}
