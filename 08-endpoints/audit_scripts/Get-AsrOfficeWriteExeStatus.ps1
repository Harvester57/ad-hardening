# Get-AsrOfficeWriteExeStatus.ps1
$AsrRulesPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
$Value = Get-ItemProperty -Path $AsrRulesPath -Name "3b576869-a4ec-4529-8536-b80a7769e899" -ErrorAction SilentlyContinue
if ($Value -and ($Value."3b576869-a4ec-4529-8536-b80a7769e899" -eq "1" -or $Value."3b576869-a4ec-4529-8536-b80a7769e899" -eq 1)) {
    Write-Output "Compliant"
    exit 0
} else {
    Write-Output "Non-Compliant"
    exit 1
}
