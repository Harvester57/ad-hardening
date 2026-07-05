# Get-DefenderAttachmentScanStatus.ps1
$Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments"
$Reg = Get-ItemProperty -Path $Path -Name "ScanWithAntiVirus" -ErrorAction SilentlyContinue
if ($Reg -and $Reg.ScanWithAntiVirus -eq 3) {
    Write-Output "Compliant"
    exit 0
} else {
    Write-Output "Non-Compliant"
    exit 1
}
