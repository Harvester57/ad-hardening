# Get-DefenderRtpStatus.ps1
$Pref = Get-MpPreference
if ($Pref.DisableRealtimeMonitoring -eq $false -and $Pref.DisableBehaviorMonitoring -eq $false -and $Pref.DisableIOAVProtection -eq $false -and $Pref.DisableScriptScanning -eq $false) {
    Write-Output "Compliant"
    exit 0
} else {
    Write-Output "Non-Compliant"
    exit 1
}
