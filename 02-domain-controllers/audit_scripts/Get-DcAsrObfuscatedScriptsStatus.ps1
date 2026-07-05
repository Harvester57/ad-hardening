# Get-DcAsrObfuscatedScriptsStatus.ps1
$AsrRulesPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
$Value = Get-ItemProperty -Path $AsrRulesPath -Name "5beb7efe-fd9a-4556-801d-275e5ffc04cc" -ErrorAction SilentlyContinue
if ($Value -and ($Value."5beb7efe-fd9a-4556-801d-275e5ffc04cc" -eq "1" -or $Value."5beb7efe-fd9a-4556-801d-275e5ffc04cc" -eq 1)) {
    Write-Output "Compliant"
    exit 0
} else {
    Write-Output "Non-Compliant"
    exit 1
}
