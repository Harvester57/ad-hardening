# Get-AsrOfficeInjectionStatus.ps1
$AsrRulesPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
$Value = Get-ItemProperty -Path $AsrRulesPath -Name "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84" -ErrorAction SilentlyContinue
if ($Value -and ($Value."75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84" -eq "1" -or $Value."75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84" -eq 1)) {
    Write-Output "Compliant"
    exit 0
} else {
    Write-Output "Non-Compliant"
    exit 1
}
