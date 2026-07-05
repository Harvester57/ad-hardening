# Get-AsrWmiPersistenceStatus.ps1
$AsrRulesPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
$Value = Get-ItemProperty -Path $AsrRulesPath -Name "e6db77e5-3df2-4cf1-b95a-636979351e5b" -ErrorAction SilentlyContinue
if ($Value -and ($Value."e6db77e5-3df2-4cf1-b95a-636979351e5b" -eq "1" -or $Value."e6db77e5-3df2-4cf1-b95a-636979351e5b" -eq 1)) {
    Write-Output "Compliant"
    exit 0
} else {
    Write-Output "Non-Compliant"
    exit 1
}
