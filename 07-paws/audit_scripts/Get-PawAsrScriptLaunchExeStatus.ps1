# Get-PawAsrScriptLaunchExeStatus.ps1
$AsrRulesPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
$Value = Get-ItemProperty -Path $AsrRulesPath -Name "d3e037e1-3eb8-44c8-a917-57927947596d" -ErrorAction SilentlyContinue
if ($Value -and ($Value."d3e037e1-3eb8-44c8-a917-57927947596d" -eq "1" -or $Value."d3e037e1-3eb8-44c8-a917-57927947596d" -eq 1)) {
    Write-Output "Compliant"
    exit 0
} else {
    Write-Output "Non-Compliant"
    exit 1
}
