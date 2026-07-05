# Get-PawDefenderOobeRtpStatus.ps1
$Reg = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "OobeEnableRtpAndSigUpdate" -ErrorAction SilentlyContinue
if ($Reg -and $Reg.OobeEnableRtpAndSigUpdate -eq 1) {
    Write-Output "Compliant"
    exit 0
} else {
    Write-Output "Non-Compliant"
    exit 1
}
