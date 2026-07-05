# Get-DefenderEdrBlockModeStatus.ps1
$Reg = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Features" -Name "PassiveRemediation" -ErrorAction SilentlyContinue
if ($Reg -and $Reg.PassiveRemediation -eq 1) {
    Write-Output "Compliant"
    exit 0
} else {
    Write-Output "Non-Compliant"
    exit 1
}
