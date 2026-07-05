# Get-DefenderMapsOverrideStatus.ps1
$Reg = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "LocalSettingOverrideSpynetReporting" -ErrorAction SilentlyContinue
if ($Reg -and $Reg.LocalSettingOverrideSpynetReporting -eq 0) {
    Write-Output "Compliant"
    exit 0
} else {
    Write-Output "Non-Compliant"
    exit 1
}
