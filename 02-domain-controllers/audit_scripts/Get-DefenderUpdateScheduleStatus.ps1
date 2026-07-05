# Get-DefenderUpdateScheduleStatus.ps1
$Reg = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates" -Name "ASSignatureDue" -ErrorAction SilentlyContinue
$RegAV = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates" -Name "AVSignatureDue" -ErrorAction SilentlyContinue
$RegDay = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates" -Name "ScheduleDay" -ErrorAction SilentlyContinue
if (($Reg -and $Reg.ASSignatureDue -eq 7) -and ($RegAV -and $RegAV.AVSignatureDue -eq 7) -and ($RegDay -and $RegDay.ScheduleDay -eq 0)) {
    Write-Output "Compliant"
    exit 0
} else {
    Write-Output "Non-Compliant"
    exit 1
}
