# Get-DefenderDisableGenericReportsStatus.ps1
$Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
$Reg = Get-ItemProperty -Path $Path -Name "DisableGenericRePorts" -ErrorAction SilentlyContinue
if ($Reg -and $Reg.DisableGenericRePorts -eq 1) {
    Write-Output "Compliant"
    exit 0
} else {
    Write-Output "Non-Compliant"
    exit 1
}
