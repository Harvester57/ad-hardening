# Get-PawDefenderQuickScanStatus.ps1
$Pref = Get-MpPreference
$Reg = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" -Name "QuickScanIncludeExclusions" -ErrorAction SilentlyContinue
$RegPack = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" -Name "DisablePackedExeScanning" -ErrorAction SilentlyContinue
if (($Pref.DisablePackedExeScanning -eq $false -or ($RegPack -and $RegPack.DisablePackedExeScanning -eq 0)) -and
    ($Reg -and $Reg.QuickScanIncludeExclusions -eq 1)) {
    Write-Output "Compliant"
    exit 0
} else {
    Write-Output "Non-Compliant"
    exit 1
}
