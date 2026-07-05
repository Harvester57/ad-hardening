# Get-PawDefenderThreatActionsStatus.ps1
$Reg = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Threats" -Name "Threats_ThreatSeverityDefaultAction" -ErrorAction SilentlyContinue
$RegSev = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction" -ErrorAction SilentlyContinue
if (($Reg -and $Reg.Threats_ThreatSeverityDefaultAction -eq 1) -and 
    ($RegSev -and $RegSev.1 -eq 2 -and $RegSev.2 -eq 2 -and $RegSev.4 -eq 2 -and $RegSev.5 -eq 2)) {
    Write-Output "Compliant"
    exit 0
} else {
    Write-Output "Non-Compliant"
    exit 1
}
