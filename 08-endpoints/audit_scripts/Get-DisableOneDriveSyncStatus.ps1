# Get-DisableOneDriveSyncStatus.ps1
$Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive"
$Reg = Get-ItemProperty -Path $Path -Name "DisableFileSyncNGSC" -ErrorAction SilentlyContinue
if ($Reg -and $Reg.DisableFileSyncNGSC -eq 1) {
    Write-Output "Compliant"
    exit 0
} else {
    Write-Output "Non-Compliant"
    exit 1
}
