# Get-DefenderAutoExclusionsStatus.ps1
$Reg = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions" -Name "DisableAutoExclusions" -ErrorAction SilentlyContinue
if ($Reg -and $Reg.DisableAutoExclusions -eq 0) {
    Write-Output "Compliant"
    exit 0
} else {
    Write-Output "Non-Compliant"
    exit 1
}
