# Get-DefenderRtpDCStatus.ps1
$Pref = Get-MpPreference
$Reg = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -ErrorAction SilentlyContinue
if ($Pref.DisableRealtimeMonitoring -eq $false -and $Pref.DisableBehaviorMonitoring -eq $false -and $Pref.DisableIOAVProtection -eq $false -and $Pref.DisableScriptScanning -eq $false -and ($Reg -and $Reg.DisableAntiSpyware -eq 0)) {
    Write-Output "Compliant"
    exit 0
} else {
    Write-Output "Non-Compliant"
    exit 1
}
