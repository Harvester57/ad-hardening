# Get-AsrEmailExecutableStatus.ps1
$AsrRulesPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
$Value = Get-ItemProperty -Path $AsrRulesPath -Name "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550" -ErrorAction SilentlyContinue
if ($Value -and ($Value."be9ba2d9-53ea-4cdc-84e5-9b1eeee46550" -eq "1" -or $Value."be9ba2d9-53ea-4cdc-84e5-9b1eeee46550" -eq 1)) {
    Write-Output "Compliant"
    exit 0
} else {
    Write-Output "Non-Compliant"
    exit 1
}
