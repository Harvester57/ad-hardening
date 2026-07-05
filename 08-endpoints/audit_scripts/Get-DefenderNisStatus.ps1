# Get-DefenderNisStatus.ps1
$Reg = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\NIS" -Name "EnableConvertWarnToBlock" -ErrorAction SilentlyContinue
$RegAsync = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\NIS" -Name "AllowSwitchToAsyncInspection" -ErrorAction SilentlyContinue
if (($Reg -and $Reg.EnableConvertWarnToBlock -eq 1) -and ($RegAsync -and $RegAsync.AllowSwitchToAsyncInspection -eq 1)) {
    Write-Output "Compliant"
    exit 0
} else {
    Write-Output "Non-Compliant"
    exit 1
}
