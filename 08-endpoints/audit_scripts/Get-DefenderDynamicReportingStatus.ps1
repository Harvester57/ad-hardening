# Get-DefenderDynamicReportingStatus.ps1
$Reg = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" -Name "EnableDynamicSignatureDroppedEventReporting" -ErrorAction SilentlyContinue
if ($Reg -and $Reg.EnableDynamicSignatureDroppedEventReporting -eq 1) {
    Write-Output "Compliant"
    exit 0
} else {
    Write-Output "Non-Compliant"
    exit 1
}
