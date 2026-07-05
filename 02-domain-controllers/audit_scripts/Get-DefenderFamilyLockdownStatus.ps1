# Get-DefenderFamilyLockdownStatus.ps1
$Reg = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Family options" -Name "UILockdown" -ErrorAction SilentlyContinue
if ($Reg -and $Reg.UILockdown -eq 1) {
    Write-Output "Compliant"
    exit 0
} else {
    Write-Output "Non-Compliant"
    exit 1
}
