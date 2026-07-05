# Get-AsrRansomwareStatus.ps1
$AsrRulesPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
$Value = Get-ItemProperty -Path $AsrRulesPath -Name "c1db55ab-c21a-4637-bb3f-a12568109d35" -ErrorAction SilentlyContinue
if ($Value -and ($Value."c1db55ab-c21a-4637-bb3f-a12568109d35" -eq "1" -or $Value."c1db55ab-c21a-4637-bb3f-a12568109d35" -eq 1)) {
    Write-Output "Compliant"
    exit 0
} else {
    Write-Output "Non-Compliant"
    exit 1
}
