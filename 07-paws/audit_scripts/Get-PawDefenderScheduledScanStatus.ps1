# Get-PawDefenderScheduledScanStatus.ps1
$Pref = Get-MpPreference
$RegDays = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" -Name "DaysWithoutCatchupQuickScan" -ErrorAction SilentlyContinue
if ($Pref.DisableEmailScanning -eq $false -and $Pref.DisableHeuristics -eq $false -and ($RegDays -and $RegDays.DaysWithoutCatchupQuickScan -eq 7)) {
    Write-Output "Compliant"
    exit 0
} else {
    Write-Output "Non-Compliant"
    exit 1
}
