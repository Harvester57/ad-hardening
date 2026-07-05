# Get-AsrPsexecWmiStatus.ps1
$AsrRulesPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
$Value = Get-ItemProperty -Path $AsrRulesPath -Name "d1e49aac-8f56-4280-b9ba-993a6d77406c" -ErrorAction SilentlyContinue
if ($Value -and ($Value."d1e49aac-8f56-4280-b9ba-993a6d77406c" -eq "1" -or $Value."d1e49aac-8f56-4280-b9ba-993a6d77406c" -eq 1)) {
    Write-Output "Compliant"
    exit 0
} else {
    Write-Output "Non-Compliant"
    exit 1
}
