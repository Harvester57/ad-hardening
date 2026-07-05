# Get-AsrOutlookChildStatus.ps1
$AsrRulesPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
$Value = Get-ItemProperty -Path $AsrRulesPath -Name "26190899-1602-49e8-8b27-eb1d0a1ce869" -ErrorAction SilentlyContinue
if ($Value -and ($Value."26190899-1602-49e8-8b27-eb1d0a1ce869" -eq "1" -or $Value."26190899-1602-49e8-8b27-eb1d0a1ce869" -eq 1)) {
    Write-Output "Compliant"
    exit 0
} else {
    Write-Output "Non-Compliant"
    exit 1
}
