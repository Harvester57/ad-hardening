# Get-PawDefenderFileHashStatus.ps1
$Pref = Get-MpPreference
$Reg = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine" -Name "EnableFileHashComputation" -ErrorAction SilentlyContinue
if ($Pref.EnableFileHashComputation -eq $true -or ($Reg -and $Reg.EnableFileHashComputation -eq 1)) {
    Write-Output "Compliant"
    exit 0
} else {
    Write-Output "Non-Compliant"
    exit 1
}
