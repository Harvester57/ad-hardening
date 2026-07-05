# Get-AsrVulnerableDriversStatus.ps1
$AsrRulesPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
$Value = Get-ItemProperty -Path $AsrRulesPath -Name "56a863a9-875e-4185-98a7-b882c64b5ce5" -ErrorAction SilentlyContinue
if ($Value -and ($Value."56a863a9-875e-4185-98a7-b882c64b5ce5" -eq "1" -or $Value."56a863a9-875e-4185-98a7-b882c64b5ce5" -eq 1)) {
    Write-Output "Compliant"
    exit 0
} else {
    Write-Output "Non-Compliant"
    exit 1
}
